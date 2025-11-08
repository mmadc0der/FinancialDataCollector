package kernel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"context"
	"time"

	"github.com/example/data-kernel/internal/auth"
	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
	"github.com/example/data-kernel/internal/logging"
	"github.com/example/data-kernel/internal/metrics"
	"github.com/example/data-kernel/internal/protocol"
	"github.com/redis/go-redis/v9"
	ssh "golang.org/x/crypto/ssh"
)

// context pooling removed; use standard contexts

type Kernel struct {
	cfg             *kernelcfg.Config
	rt              *router
	rd              *data.Redis
	pg              *data.Postgres
	au              *auth.Verifier
	producerTracker *activityTracker
	subjectTracker  *activityTracker
}

func NewKernel(configPath string) (*Kernel, error) {
	cfg, err := kernelcfg.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return &Kernel{
		cfg: cfg,
		producerTracker: newActivityTracker(5*time.Minute, func(count int) {
			metrics.ProducerActiveGauge.Set(float64(count))
		}),
		subjectTracker: newActivityTracker(5*time.Minute, func(count int) {
			metrics.SubjectActiveGauge.Set(float64(count))
		}),
	}, nil
}

func (k *Kernel) Start(ctx context.Context) error {
	// Initialize logging first so migrations are logged properly
	stopLog := logging.Init(k.cfg.Logging)
	defer stopLog()
	ev := logging.NewEventLogger()

	ev.Infra("start", "kernel", "success", fmt.Sprintf("kernel starting on %s", k.cfg.Server.Listen))
	ev.Infra("config", "redis", "success", fmt.Sprintf("addr=%s,prefix=%s,stream=%s,group=%s", k.cfg.Redis.Addr, k.cfg.Redis.KeyPrefix, k.cfg.Redis.Stream, k.cfg.Redis.ConsumerGroup))

	// Router handles durable persistence (Postgres-first, spill fallback) and optional publish
	r, err := newRouter(k.cfg, func(ids ...string) {
		if k.rd == nil || len(ids) == 0 {
			return
		}
		// best-effort ack with short timeout per batch
		_ = k.rd.Ack(context.Background(), ids...)
		metrics.RedisAckTotal.Add(float64(len(ids)))
	})
	if err != nil {
		return err
	}
	k.rt = r
	// Share Postgres instance from router to avoid duplicate initialization/migrations
	if r != nil {
		k.pg = r.pg
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	// Auth endpoints (mandatory)
	mux.HandleFunc("/auth", k.handleListPending)
	mux.HandleFunc("/auth/review", k.handleReview)
	mux.HandleFunc("/auth/revoke", k.handleRevokeToken)
	// Configure strict mTLS for admin server
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	checkFile := func(path, field string) error {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("%s not configured", field)
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		if info.IsDir() {
			return fmt.Errorf("%s points to directory", field)
		}
		return nil
	}
	tlsEnabled := false
	if k.cfg.Server.TLS.CertFile != "" || k.cfg.Server.TLS.KeyFile != "" || k.cfg.Server.TLS.ClientCAFile != "" {
		if err := checkFile(k.cfg.Server.TLS.CertFile, "server.tls.cert_file"); err != nil {
			ev.Infra("config", "tls", "failed", err.Error())
			return err
		}
		ev.Infra("config", "tls", "success", fmt.Sprintf("server.tls.cert_file validated: path=%s", k.cfg.Server.TLS.CertFile))
		if err := checkFile(k.cfg.Server.TLS.KeyFile, "server.tls.key_file"); err != nil {
			ev.Infra("config", "tls", "failed", err.Error())
			return err
		}
		ev.Infra("config", "tls", "success", fmt.Sprintf("server.tls.key_file validated: path=%s", k.cfg.Server.TLS.KeyFile))
		tlsEnabled = true
		if k.cfg.Server.TLS.RequireClientCert {
			if err := checkFile(k.cfg.Server.TLS.ClientCAFile, "server.tls.client_ca_file"); err != nil {
				ev.Infra("config", "tls", "failed", err.Error())
				return err
			}
			ev.Infra("config", "tls", "success", fmt.Sprintf("server.tls.client_ca_file validated: path=%s", k.cfg.Server.TLS.ClientCAFile))
		}
		if k.cfg.Server.TLS.ClientCAFile != "" {
			caBytes, err := os.ReadFile(k.cfg.Server.TLS.ClientCAFile)
			if err != nil {
				err = fmt.Errorf("read client ca: %w", err)
				ev.Infra("config", "tls", "failed", err.Error())
				return err
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caBytes) {
				err = errors.New("bad client ca")
				ev.Infra("config", "tls", "failed", err.Error())
				return err
			}
			ev.Infra("config", "tls", "success", fmt.Sprintf("server.tls.client_ca_file loaded: path=%s subjects=%d", k.cfg.Server.TLS.ClientCAFile, len(caPool.Subjects())))
			if k.cfg.Server.TLS.RequireClientCert {
				tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
				tlsCfg.ClientCAs = caPool
			}
		} else if k.cfg.Server.TLS.RequireClientCert {
			err := errors.New("server.tls.client_ca_file required when require_client_cert=true")
			ev.Infra("config", "tls", "failed", err.Error())
			return err
		}
		if k.cfg.Server.TLS.RequireClientCert {
			ev.Infra("config", "tls", "success", fmt.Sprintf("tls_enabled addr=%s client_auth=require", k.cfg.Server.Listen))
		} else {
			ev.Infra("config", "tls", "success", fmt.Sprintf("tls_enabled addr=%s client_auth=optional", k.cfg.Server.Listen))
		}
	} else {
		ev.Infra("config", "tls", "info", "tls_disabled: serving plain HTTP on "+k.cfg.Server.Listen)
	}
	server := &http.Server{Addr: k.cfg.Server.Listen, Handler: mux, TLSConfig: tlsCfg}

	// Auth verifier (mandatory)
	v, err := auth.NewVerifier(k.cfg.Auth, k.pg, k.rd)
	if err != nil {
		return err
	}
	k.au = v
	ev.Infra("init", "auth", "success", fmt.Sprintf("verifier initialized: issuer=%s,audience=%s", k.cfg.Auth.Issuer, k.cfg.Auth.Audience))

	// Start Redis consumer (mandatory)
	if rd, err := data.NewRedis(k.cfg.Redis); err == nil {
		k.rd = rd
		// best-effort create groups for all streams BEFORE starting consumers to avoid race with producers
		_ = k.rd.EnsureGroup(ctx)
		if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
			// Fixed protocol streams
			_ = k.rd.C().XGroupCreateMkStream(ctx, prefixed(k.cfg.Redis.KeyPrefix, "register"), k.cfg.Redis.ConsumerGroup, "0-0").Err()
			_ = k.rd.C().XGroupCreateMkStream(ctx, prefixed(k.cfg.Redis.KeyPrefix, "subject:register"), k.cfg.Redis.ConsumerGroup, "0-0").Err()
			_ = k.rd.C().XGroupCreateMkStream(ctx, prefixed(k.cfg.Redis.KeyPrefix, "token:exchange"), k.cfg.Redis.ConsumerGroup, "0-0").Err()
			_ = k.rd.C().XGroupCreateMkStream(ctx, prefixed(k.cfg.Redis.KeyPrefix, "schema:upgrade"), k.cfg.Redis.ConsumerGroup, "0-0").Err()
		}
		go k.consumeRedis(ctx)
		// registration stream consumer (fixed stream)
		go k.consumeRegister(ctx)
		// subject registration consumer (fixed stream)
		go k.consumeSubjectRegister(ctx)
		// token exchange consumer (fixed stream)
		go k.consumeTokenExchange(ctx)
		// schema upgrade consumer (dedicated stream)
		go k.consumeSchemaUpgrade(ctx)
	} else {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// simple shutdown: stop HTTP, close router resources, close Redis
		_ = server.Shutdown(shutdownCtx)
		if k.rt != nil {
			k.rt.close()
		}
		if k.rd != nil {
			_ = k.rd.Close()
		}
		if k.pg != nil {
			k.pg.Close()
		}
	}()

	if tlsEnabled {
		if err := server.ListenAndServeTLS(k.cfg.Server.TLS.CertFile, k.cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// consumeRedis reads events from Redis Streams and enqueues to router
func (k *Kernel) consumeRedis(ctx context.Context) {
	ev := logging.NewEventLogger()

	consumer := fmt.Sprintf("%s-%d", "kernel", time.Now().UnixNano())
	count := k.cfg.Redis.ReadCount
	if count <= 0 {
		count = 100
	}
	block := time.Duration(k.cfg.Redis.BlockMs) * time.Millisecond
	if block <= 0 {
		block = 5 * time.Second
	}
	dlq := prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.DLQStream)

	for ctx.Err() == nil {

		t0 := time.Now()
		streams, err := k.rd.ReadBatch(ctx, consumer, count, block)
		if err != nil {
			// backoff on errors
			ev.Infra("read", "redis", "failed", fmt.Sprintf("redis batch read error: %v", err))
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if len(streams) > 0 {
			metrics.RedisBatchDuration.Observe(time.Since(t0).Seconds())
		}
		// Update stream length and pending approximations (best-effort)
		if k.rd != nil && k.rd.C() != nil {
			info, err := k.rd.C().XInfoStream(ctx, prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.Stream)).Result()
			if err != nil {
				ev.Infra("read", "redis", "failed", fmt.Sprintf("failed to get stream info: %v", err))
			} else if info.Length > 0 {
				metrics.RedisStreamLenGauge.Set(float64(info.Length))
			}
			// pending: XINFO GROUPS returns per-group pending
			groups, err := k.rd.C().XInfoGroups(ctx, prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.Stream)).Result()
			if err != nil {
				ev.Infra("read", "redis", "failed", fmt.Sprintf("failed to get group info: %v", err))
			} else {
				for _, g := range groups {
					if strings.EqualFold(g.Name, k.cfg.Redis.ConsumerGroup) {
						metrics.RedisPendingGauge.Set(float64(g.Pending))
					}
				}
			}
		}

		for _, s := range streams {
			for _, m := range s.Messages {
				observeRedisLag(m.ID)
				globalMetricsBatcher.IncRedisRead()
				id, payload, token := data.DecodeMessage(m)
				if len(payload) == 0 {
					_ = k.rd.ToDLQ(ctx, dlq, id, []byte("{}"), "empty_payload")
					ev.Infra("error", "redis", "failed", fmt.Sprintf("empty payload for event id: %s", id))
					globalMetricsBatcher.IncRedisDLQ()
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack empty payload: %v", ackErr))
					} else {
						globalMetricsBatcher.IncRedisAck()
					}
					continue
				}
				// Authenticate and capture producer/subject from token
				var producerID, subjectIDFromToken, jti string
				{
					if pid, sid, j, err := k.au.Verify(ctx, token); err != nil {
						globalMetricsBatcher.IncAuthDenied()
						_ = k.rd.ToDLQ(ctx, dlq, id, payload, "unauthenticated")
						ev.Auth("failure", "", "", false, fmt.Sprintf("token verification failed for event %s: %v", id, err))
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack auth denied: %v", ackErr))
						} else {
							globalMetricsBatcher.IncRedisAck()
						}
						continue
					} else {
						producerID, subjectIDFromToken, jti = pid, sid, j
					}
				}
				// If producer is disabled (deregistered), reject until re-registration
				if producerID != "" {
					if disabled, err := k.pg.IsProducerDisabled(ctx, producerID); err == nil && disabled {
						_ = k.rd.ToDLQ(ctx, dlq, id, payload, "producer_disabled")
						ev.Authorization("deny", producerID, "ingest", "producer_disabled")
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack disabled producer: %v", ackErr))
						} else {
							globalMetricsBatcher.IncRedisAck()
						}
						continue
					}
				}
				_ = jti // reserved for future gating
				// Parse lean event JSON from payload
				var eventData struct {
					EventID   string          `json:"event_id"`
					TS        string          `json:"ts"`
					SubjectID string          `json:"subject_id"`
					Payload   json.RawMessage `json:"payload"`
					Tags      json.RawMessage `json:"tags"`
				}
				if err := json.Unmarshal(payload, &eventData); err != nil || eventData.EventID == "" || eventData.TS == "" || eventData.SubjectID == "" || len(eventData.Payload) == 0 {
					_ = k.rd.ToDLQ(ctx, dlq, id, payload, "bad_event_json")
					ev.Infra("error", "redis", "failed", fmt.Sprintf("bad event JSON for id: %s", id))
					globalMetricsBatcher.IncRedisDLQ()
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack bad JSON: %v", ackErr))
					} else {
						globalMetricsBatcher.IncRedisAck()
					}
					continue
				}
				// if token has sid, enforce match
				if subjectIDFromToken != "" && !strings.EqualFold(subjectIDFromToken, eventData.SubjectID) {
					_ = k.rd.ToDLQ(ctx, dlq, id, payload, "subject_mismatch_token")
					ev.Auth("failure", "", "", false, fmt.Sprintf("subject mismatch: token=%s,event=%s", subjectIDFromToken, eventData.SubjectID))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack subject mismatch: %v", ackErr))
					} else {
						globalMetricsBatcher.IncRedisAck()
					}
					continue
				}
				// Verify producer-subject binding
				if producerID != "" {
					if ok, err := k.pg.CheckProducerSubject(ctx, producerID, eventData.SubjectID); err != nil || !ok {
						_ = k.rd.ToDLQ(ctx, dlq, id, payload, "producer_subject_forbidden")
						ev.Auth("failure", "", "", false, fmt.Sprintf("producer-subject binding forbidden: producer=%s,subject=%s", producerID, eventData.SubjectID))
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack forbidden binding: %v", ackErr))
						} else {
							globalMetricsBatcher.IncRedisAck()
						}
						continue
					}
				}
				// Resolve schema via Redis cache; on miss, fallback to Postgres and backfill cache
				var schemaID string
				if sid, ok := k.rd.SchemaCacheGet(ctx, eventData.SubjectID); ok {
					schemaID = sid
				} else {
					// Fallback: query Postgres for current schema_id and cache it
					if k.pg != nil {
						if sid, err := k.pg.GetCurrentSchemaID(ctx, eventData.SubjectID); err == nil && sid != "" {
							schemaID = sid
							ttl := time.Duration(k.cfg.Performance.SchemaCacheTTLSeconds) * time.Second
							if ttl <= 0 {
								ttl = time.Hour
							}
							_ = k.rd.SchemaCacheSet(ctx, eventData.SubjectID, schemaID, ttl)
						}
					}
					if schemaID == "" {
						_ = k.rd.ToDLQ(ctx, dlq, id, payload, "schema_missing")
						ev.Infra("error", "postgres", "failed", fmt.Sprintf("schema missing for subject: %s", eventData.SubjectID))
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack schema missing: %v", ackErr))
						} else {
							globalMetricsBatcher.IncRedisAck()
						}
						continue
					}
				}
				// producer/subject activity metrics
				if producerID != "" {
					metrics.ProducerEventTotal.WithLabelValues(producerID).Inc()
					k.producerTracker.mark(producerID)
				}
				if eventData.SubjectID != "" {
					metrics.SubjectEventTotal.WithLabelValues(eventData.SubjectID).Inc()
					k.subjectTracker.mark(eventData.SubjectID)
				}
				// route for durable handling; ack will be done after persistence via router callback
				k.rt.handleLeanEvent(m.ID, eventData.EventID, eventData.TS, eventData.SubjectID, producerID, eventData.Payload, eventData.Tags, schemaID)
			}
		}
	}
}

func prefixed(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + key
}

// coalesceJSON returns raw JSON string or empty object if nil/empty.
func coalesceJSON(b json.RawMessage) string {
	if len(b) == 0 || string(b) == "" {
		return "{}"
	}
	return string(b)
}

// envelope adaptation removed

// sendSubjectResponse sends a response message to per-producer subject response stream with TTL
func (k *Kernel) sendSubjectResponse(ctx context.Context, producerID string, values map[string]any) {
	if k == nil || k.rd == nil || k.rd.C() == nil || producerID == "" {
		return
	}
	respStream := prefixed(k.cfg.Redis.KeyPrefix, "subject:resp:"+producerID)
	_ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: respStream, Values: values}).Err()
	ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	_ = k.rd.C().Expire(ctx, respStream, ttl).Err()
}

// consumeSubjectRegister handles subject registration stream signed by SSH pubkey
// Message fields: pubkey, payload (canonical JSON), nonce, sig
// Payload supports ops: set_current (default) and upgrade_auto
func (k *Kernel) consumeSubjectRegister(ctx context.Context) {
	ev := logging.NewEventLogger()

	if k.rd == nil || k.pg == nil {
		ev.Infra("error", "redis", "failed", "subject register consumer disabled: dependencies unavailable")
		return
	}
	stream := prefixed(k.cfg.Redis.KeyPrefix, "subject:register")
	if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
		if err := k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "0-0").Err(); err != nil {
			if !strings.Contains(err.Error(), "BUSYGROUP") {
				ev.Infra("error", "redis", "failed", fmt.Sprintf("failed to create subject register consumer group: %v", err))
			}
		}
	}
	consumer := fmt.Sprintf("%s-subreg-%d", "kernel", time.Now().UnixNano())
	for ctx.Err() == nil {
		res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second}).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			ev.Infra("read", "redis", "failed", fmt.Sprintf("subject register stream read error: %v", err))
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if len(res) == 0 {
			continue
		}
		for _, s := range res {
			for _, m := range s.Messages {
				pubkey, _ := m.Values["pubkey"].(string)
				payloadStr, _ := m.Values["payload"].(string)
				nonce, _ := m.Values["nonce"].(string)
				sigB64, _ := m.Values["sig"].(string)
				fp0 := ""
				if pubkey != "" {
					fp0 = sshFingerprint([]byte(pubkey))
				}

				if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" {
					ev.Registration("message_invalid", fp0, "", "failed", fmt.Sprintf("missing_fields: stream=%s id=%s", stream, m.ID))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack missing fields: %v", ackErr))
					}
					continue
				}
				// Verify signature and CA; ensure key approved; get producer_id
				producerID := ""
				{
					fp := sshFingerprint([]byte(pubkey))
					parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
					if err != nil {
						ev.Registration("payload_invalid", fp, "", "failed", fmt.Sprintf("pubkey_parse_error: %v", err))
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack parse error: %v", ackErr))
						}
						continue
					}
					if k.cfg.Auth.ProducerSSHCA != "" {
						caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
						if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
							parsedPub = cert.Key
						} else {
							parsedPub = nil
						}
					}
					okSig := false
					if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
						if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
							canon := string(protocol.CanonicalizeJSON([]byte(payloadStr)))
							msg := []byte(canon + "." + nonce)
							sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
							if decErr != nil {
								sigBytes, _ = base64.StdEncoding.DecodeString(sigB64)
							}
							if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) {
								okSig = true
							}
						}
					}
					if !okSig {
						ev.Registration("signature_invalid", fp, "", "failed", "signature_verification_failed")
						metrics.CanonicalVerifyFail.Inc()
						// best-effort send error response if producer is known
						if status, pidPtr, _ := k.pg.GetKeyStatus(ctx, fp); pidPtr != nil && *pidPtr != "" {
							_ = status // status not used for this error
							k.sendSubjectResponse(ctx, *pidPtr, map[string]any{"error": "invalid_sig", "reason": "signature_verification_failed"})
						}
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack bad signature: %v", ackErr))
						}
						continue
					}
					status, pidPtr, err := k.pg.GetKeyStatus(ctx, fp)
					if err != nil || status != "approved" || pidPtr == nil || *pidPtr == "" {
						ev.Registration("status_denied", fp, "", "denied", "key_not_approved")
						if pidPtr != nil && *pidPtr != "" {
							k.sendSubjectResponse(ctx, *pidPtr, map[string]any{"error": "key_not_approved", "status": status})
						}
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack not approved: %v", ackErr))
						}
						continue
					}
					producerID = *pidPtr
					// replay protection - check after we have producer ID
					if k.rd != nil && k.rd.C() != nil {
						key := prefixed(k.cfg.Redis.KeyPrefix, "nonce:subject:"+producerID+":"+nonce)
						ok, err := k.rd.C().SetNX(ctx, key, 1, 10*time.Minute).Result()
						if err != nil {
							ev.Infra("error", "redis", "failed", fmt.Sprintf("subject register nonce guard error: %v", err))
						} else if !ok {
							ev.Registration("nonce_replay", fp, producerID, "failed", "duplicate_nonce")
							k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "replay"})
							if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
								ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack replay: %v", ackErr))
							}
							continue
						}
					}
					if !k.checkRateLimit(ctx, "subject", producerID) {
						ev.Registration("rate_limited", fp, producerID, "denied", fmt.Sprintf("rate_limited: key=%s", producerID))
						// best-effort notify client
						k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "rate_limited"})
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack rate limited: %v", ackErr))
						}
						continue
					}
				}
				var req struct {
					Op          string          `json:"op"`
					SubjectKey  string          `json:"subject_key"`
					SchemaName  string          `json:"schema_name"`
					SchemaBody  json.RawMessage `json:"schema_body"`
					SchemaDelta json.RawMessage `json:"schema_delta"`
					Attrs       json.RawMessage `json:"attrs"`
					AttrsDelta  json.RawMessage `json:"attrs_delta"`
				}
				if payloadStr == "" || json.Unmarshal([]byte(payloadStr), &req) != nil || req.SubjectKey == "" {
					ev.Registration("payload_invalid", fp0, producerID, "failed", "invalid_payload")
					if producerID != "" {
						k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload"})
					}
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack invalid payload: %v", ackErr))
					}
					continue
				}
				// Strict op validation before any DB calls
				switch strings.ToLower(strings.TrimSpace(req.Op)) {
				case "register":
					if strings.TrimSpace(req.SchemaName) == "" || len(req.SchemaBody) == 0 || strings.TrimSpace(string(req.SchemaBody)) == "" {
						ev.Registration("payload_invalid", fp0, producerID, "failed", "missing_schema_name_or_body")
						if producerID != "" {
							k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload", "details": "register requires schema_name and schema_body"})
						}
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack validation error: %v", ackErr))
						}
						continue
					}
					if len(strings.TrimSpace(string(req.SchemaDelta))) > 0 || len(strings.TrimSpace(string(req.AttrsDelta))) > 0 {
						ev.Registration("payload_invalid", fp0, producerID, "failed", "delta_fields_not_allowed_for_register")
						if producerID != "" {
							k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload", "details": "delta fields not allowed for register"})
						}
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack validation error: %v", ackErr))
						}
						continue
					}
				case "upgrade":
					if strings.TrimSpace(req.SchemaName) == "" || len(strings.TrimSpace(string(req.SchemaDelta))) == 0 {
						ev.Registration("payload_invalid", fp0, producerID, "failed", "missing_schema_name_or_delta")
						if producerID != "" {
							k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload", "details": "upgrade requires schema_name and schema_delta"})
						}
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack validation error: %v", ackErr))
						}
						continue
					}
					if len(strings.TrimSpace(string(req.SchemaBody))) > 0 {
						ev.Registration("payload_invalid", fp0, producerID, "failed", "schema_body_not_allowed_for_upgrade")
						if producerID != "" {
							k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload", "details": "schema_body not allowed for upgrade"})
						}
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack validation error: %v", ackErr))
						}
						continue
					}
				default:
					ev.Registration("payload_invalid", fp0, producerID, "failed", fmt.Sprintf("unknown_op: %s", req.Op))
					if producerID != "" {
						k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "unknown_op", "op": req.Op})
					}
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack unknown op: %v", ackErr))
					}
					continue
				}
				var sid string
				var schemaID string
				var schemaName string
				var schemaVersion int
				switch strings.ToLower(strings.TrimSpace(req.Op)) {
				case "upgrade":
					var unchanged bool
					sid, schemaID, schemaVersion, unchanged, err = k.pg.UpgradeSubjectSchemaIncremental(ctx, req.SubjectKey, req.SchemaName, []byte(coalesceJSON(req.SchemaDelta)), []byte(coalesceJSON(req.AttrsDelta)))
					_ = unchanged
					schemaName = req.SchemaName
					if err != nil {
						ev.Infra("write", "postgres", "failed", fmt.Sprintf("subject register upgrade error: %v", err))
						if producerID != "" {
							k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "upgrade_failed", "reason": err.Error()})
						}
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack upgrade error: %v", ackErr))
						}
						continue
					}
				case "register":
					var unchanged bool
					sid, schemaID, schemaVersion, unchanged, err = k.pg.BootstrapSubjectWithSchema(ctx, req.SubjectKey, req.SchemaName, []byte(coalesceJSON(req.SchemaBody)), []byte(coalesceJSON(req.Attrs)))
					_ = unchanged
					schemaName = req.SchemaName
					if err != nil {
						ev.Infra("write", "postgres", "failed", fmt.Sprintf("subject register error: %v", err))
						if producerID != "" {
							k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "register_failed", "reason": err.Error()})
						}
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack register error: %v", ackErr))
						}
						continue
					}
				}
				// Set current schema and cache
				if sid != "" && schemaID != "" {
					_ = k.pg.SetCurrentSubjectSchema(ctx, sid, schemaID)
					_ = k.rd.SchemaCacheSet(ctx, sid, schemaID, time.Hour)
					if producerID != "" {
						_ = k.pg.BindProducerSubject(ctx, producerID, sid)
					}
				}
				// Respond on per-producer stream
				if producerID != "" {
					resp := map[string]any{"status": "ok", "producer_id": producerID, "subject_id": sid, "schema_id": schemaID}
					if schemaName != "" {
						resp["schema_name"] = schemaName
					}
					if schemaVersion > 0 {
						resp["schema_version"] = schemaVersion
					}
					k.sendSubjectResponse(ctx, producerID, resp)
					ev.Registration("success", fp0, producerID, "success", fmt.Sprintf("completed: op=%s schema=%s", strings.TrimSpace(req.Op), schemaName))
				} else {
					ev.Infra("error", "kernel", "failed", "no_producer")
				}
				if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
					ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack subject register: %v", ackErr))
				}
			}
		}
	}
}

// consumeTokenExchange handles token issuance/renewal via either approved pubkey signature or a valid existing token
func (k *Kernel) consumeTokenExchange(ctx context.Context) {
	ev := logging.NewEventLogger()

	if k.rd == nil || k.pg == nil || k.au == nil {
		ev.Infra("error", "redis", "failed", "token exchange consumer disabled: dependencies unavailable")
		return
	}
	stream := prefixed(k.cfg.Redis.KeyPrefix, "token:exchange")
	if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
		if err := k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "0-0").Err(); err != nil {
			if !strings.Contains(err.Error(), "BUSYGROUP") {
				ev.Infra("error", "redis", "failed", fmt.Sprintf("failed to create token exchange consumer group: %v", err))
			}
		}
	}
	consumer := fmt.Sprintf("%s-token-%d", "kernel", time.Now().UnixNano())

	for ctx.Err() == nil {
		res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second}).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			ev.Infra("read", "redis", "failed", fmt.Sprintf("token exchange stream read error: %v", err))
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if len(res) == 0 {
			continue
		}

		for _, s := range res {
			for _, m := range s.Messages {
				// Path 1: renewal with existing token
				if tok, ok := m.Values["token"].(string); ok && tok != "" {
					pid, sid, jti, err := k.au.Verify(ctx, tok)
					if err != nil {
						ev.Token("verify", "", "", "", false, fmt.Sprintf("token verification failed: %v", err))
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack verify error: %v", ackErr))
						}
						continue
					}
					// Deny renewal for disabled producers
					if disabled, derr := k.pg.IsProducerDisabled(ctx, pid); derr == nil && disabled {
						ev.Token("exchange", pid, sid, jti, false, "producer_disabled")
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack disabled producer: %v", ackErr))
						}
						continue
					}
					if t, newJti, exp, ierr := k.au.Issue(ctx, pid, time.Hour, "exchange", ""); ierr == nil {
						ev.Token("exchange", pid, sid, newJti, true, "")
						respStream := prefixed(k.cfg.Redis.KeyPrefix, "token:resp:"+pid)
						if err := k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: respStream, Values: map[string]any{"producer_id": pid, "token": t, "exp": exp.UTC().Format(time.RFC3339Nano)}}).Err(); err != nil {
							ev.Infra("write", "redis", "failed", fmt.Sprintf("failed to write token response: %v", err))
						} else {
							// Set TTL on token response stream to prevent accumulation of stale responses
							ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
							if ttl <= 0 {
								ttl = 5 * time.Minute
							}
							if expireErr := k.rd.C().Expire(ctx, respStream, ttl).Err(); expireErr != nil {
								ev.Infra("error", "redis", "failed", fmt.Sprintf("failed to set TTL on token response stream: %v", expireErr))
							}
						}
					} else {
						ev.Token("exchange", pid, sid, "", false, fmt.Sprintf("token issue failed: %v", ierr))
					}
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack token exchange: %v", ackErr))
					}
					continue
				}
				// Path 2: new token via approved pubkey + signature
				pubkey, _ := m.Values["pubkey"].(string)
				payloadStr, _ := m.Values["payload"].(string)
				nonce, _ := m.Values["nonce"].(string)
				sigB64, _ := m.Values["sig"].(string)
				if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" {
					ev.Token("exchange", "", "", "", false, "missing_fields")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack missing fields: %v", ackErr))
					}
					continue
				}
				fp := sshFingerprint([]byte(pubkey))
				// verify signature as in registration
				parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
				if err != nil {
					ev.Token("exchange", "", "", "", false, fmt.Sprintf("pubkey parse error: %v", err))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack parse error: %v", ackErr))
					}
					continue
				}
				if k.cfg.Auth.ProducerSSHCA != "" {
					caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
					if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
						parsedPub = cert.Key
					} else {
						parsedPub = nil
					}
				}
				okSig := false
				if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
					if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
						// Verify exact bytes as sent by client (no re-canonicalization)
						canon := string(protocol.CanonicalizeJSON([]byte(payloadStr)))
						msg := []byte(canon + "." + nonce)
						sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
						if decErr != nil {
							sigBytes, _ = base64.StdEncoding.DecodeString(sigB64)
						}
						if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) {
							okSig = true
						}
					}
				}
				if !okSig {
					metrics.CanonicalVerifyFail.Inc()
					ev.Token("exchange", "", "", "", false, "signature_verification_failed")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack signature error: %v", ackErr))
					}
					continue
				}
				status, producerID, err := k.pg.GetKeyStatus(ctx, fp)
				if err != nil {
					ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to get key status: %v", err))
					ev.Token("exchange", "", "", "", false, fmt.Sprintf("status_check_error: %v", err))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack status error: %v", ackErr))
					}
					continue
				}
				if status == "" {
					ev.Token("exchange", "", "", "", false, "unknown_key")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack unknown key: %v", ackErr))
					}
					continue
				}
				if status != "approved" {
					ev.Token("exchange", "", "", "", false, fmt.Sprintf("key_not_approved: status=%s", status))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack not approved: %v", ackErr))
					}
					continue
				}
				if producerID == nil || *producerID == "" {
					ev.Token("exchange", "", "", "", false, "no_producer_id")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack no producer: %v", ackErr))
					}
					continue
				}
				// Deny token issue when producer disabled
				if disabled, derr := k.pg.IsProducerDisabled(ctx, *producerID); derr == nil && disabled {
					ev.Token("exchange", *producerID, "", "", false, "producer_disabled")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack disabled: %v", ackErr))
					}
					continue
				}

				// Rate limiting check for token exchange
				if !k.checkRateLimit(ctx, "token", *producerID) {
					ev.Token("exchange", *producerID, "", "", false, "rate_limited")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack rate limited: %v", ackErr))
					}
					continue // silent drop for rate limited requests
				}

				if t, jti, exp, ierr := k.au.Issue(ctx, *producerID, time.Hour, "exchange", fp); ierr == nil {
					ev.Token("exchange", *producerID, "", jti, true, "")
					respStream := prefixed(k.cfg.Redis.KeyPrefix, "token:resp:"+*producerID)
					err := k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: respStream, Values: map[string]any{"fingerprint": fp, "producer_id": *producerID, "token": t, "exp": exp.UTC().Format(time.RFC3339Nano)}}).Err()
					if err != nil {
						ev.Infra("write", "redis", "failed", fmt.Sprintf("failed to write token response: %v", err))
					} else {
						// Set TTL on token response stream to prevent accumulation of stale responses
						ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
						if ttl <= 0 {
							ttl = 5 * time.Minute
						}
						if expireErr := k.rd.C().Expire(ctx, respStream, ttl).Err(); expireErr != nil {
							ev.Infra("error", "redis", "failed", fmt.Sprintf("failed to set TTL on token response stream: %v", expireErr))
						}
					}
				} else {
					ev.Token("exchange", *producerID, "", "", false, fmt.Sprintf("token issue failed: %v", ierr))
				}
				if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
					ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack token exchange: %v", ackErr))
				}
			}
		}
	}
}

// consumeSchemaUpgrade handles dedicated schema upgrade requests signed by producer key
// Stream: prefix+"schema:upgrade"; fields: pubkey, payload, nonce, sig
// Payload: { subject_key, schema_name, schema_body, attrs? }
func (k *Kernel) consumeSchemaUpgrade(ctx context.Context) {
	ev := logging.NewEventLogger()

	if k.rd == nil || k.pg == nil {
		ev.Infra("error", "redis", "failed", "schema upgrade consumer disabled: dependencies unavailable")
		return
	}
	stream := prefixed(k.cfg.Redis.KeyPrefix, "schema:upgrade")
	if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
		if err := k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "0-0").Err(); err != nil {
			if !strings.Contains(err.Error(), "BUSYGROUP") {
				ev.Infra("error", "redis", "failed", fmt.Sprintf("failed to create schema upgrade consumer group: %v", err))
			}
		}
	}
	consumer := fmt.Sprintf("%s-schup-%d", "kernel", time.Now().UnixNano())
	for ctx.Err() == nil {
		res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second}).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			ev.Infra("read", "redis", "failed", fmt.Sprintf("schema upgrade stream read error: %v", err))
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if len(res) == 0 {
			continue
		}
		for _, s := range res {
			for _, m := range s.Messages {
				pubkey, _ := m.Values["pubkey"].(string)
				payloadStr, _ := m.Values["payload"].(string)
				nonce, _ := m.Values["nonce"].(string)
				sigB64, _ := m.Values["sig"].(string)
				if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" {
					ev.Registration("message_invalid", "", "", "failed", fmt.Sprintf("missing_fields: stream=%s id=%s", stream, m.ID))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack missing fields: %v", ackErr))
					}
					continue
				}
				// Verify signature and approved producer
				fp := sshFingerprint([]byte(pubkey))
				parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
				if err != nil {
					ev.Registration("payload_invalid", fp, "", "failed", fmt.Sprintf("pubkey_parse_error: %v", err))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack parse error: %v", ackErr))
					}
					continue
				}
				if k.cfg.Auth.ProducerSSHCA != "" {
					caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
					if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
						parsedPub = cert.Key
					} else {
						parsedPub = nil
					}
				}
				okSig := false
				if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
					if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
						// Verify exact bytes as sent by client (no re-canonicalization)
						canon := string(protocol.CanonicalizeJSON([]byte(payloadStr)))
						msg := []byte(canon + "." + nonce)
						sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
						if decErr != nil {
							sigBytes, _ = base64.StdEncoding.DecodeString(sigB64)
						}
						if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) {
							okSig = true
						}
					}
				}
				if !okSig {
					ev.Registration("signature_invalid", fp, "", "failed", "signature_verification_failed")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack bad signature: %v", ackErr))
					}
					continue
				}
				// replay protection moved to after producer resolution
				status, pidPtr, err := k.pg.GetKeyStatus(ctx, fp)
				if err != nil || status != "approved" || pidPtr == nil || *pidPtr == "" {
					ev.Registration("status_denied", fp, "", "denied", "key_not_approved")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack not approved: %v", ackErr))
					}
					continue
				}
				producerID := *pidPtr
				// replay protection (after producerID known)
				if k.rd != nil && k.rd.C() != nil {
					key := prefixed(k.cfg.Redis.KeyPrefix, "nonce:schema:"+producerID+":"+nonce)
					ok, err := k.rd.C().SetNX(ctx, key, 1, 10*time.Minute).Result()
					if err != nil {
						ev.Infra("error", "redis", "failed", fmt.Sprintf("schema upgrade nonce guard error: %v", err))
						// allow on error
					} else if !ok {
						ev.Registration("nonce_replay", fp, producerID, "failed", "duplicate_nonce")
						if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
							ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack replay: %v", ackErr))
						}
						continue
					}
				}
				if !k.checkRateLimit(ctx, "schema", producerID) {
					ev.Registration("rate_limited", fp, producerID, "denied", fmt.Sprintf("rate_limited: key=%s", producerID))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack rate limited: %v", ackErr))
					}
					continue
				}

				// Parse payload
				var req struct {
					SubjectKey string          `json:"subject_key"`
					SchemaName string          `json:"schema_name"`
					SchemaBody json.RawMessage `json:"schema_body"`
					Attrs      json.RawMessage `json:"attrs"`
				}
				if payloadStr == "" || json.Unmarshal([]byte(payloadStr), &req) != nil || req.SubjectKey == "" || req.SchemaName == "" || len(req.SchemaBody) == 0 {
					ev.Registration("payload_invalid", fp, producerID, "failed", "invalid_payload")
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack invalid payload: %v", ackErr))
					}
					continue
				}
				// Perform atomic upgrade (auto-assign next version)
				sid, schemaID, version, uerr := k.pg.UpgradeSubjectSchemaAuto(ctx, req.SubjectKey, req.SchemaName, []byte(coalesceJSON(req.SchemaBody)), []byte(coalesceJSON(req.Attrs)), true)
				if uerr != nil {
					ev.Infra("write", "postgres", "failed", fmt.Sprintf("schema upgrade error: %v", uerr))
					if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
						ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack upgrade error: %v", ackErr))
					}
					continue
				}
				_ = k.rd.SchemaCacheSet(ctx, sid, schemaID, time.Hour)
				_ = k.pg.BindProducerSubject(ctx, producerID, sid)
				// Respond via subject:resp:<producer_id>
				resp := map[string]any{"subject_id": sid, "schema_id": schemaID, "schema_name": req.SchemaName, "schema_version": version}
				respStream := prefixed(k.cfg.Redis.KeyPrefix, "subject:resp:"+producerID)
				if err := k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: respStream, Values: resp}).Err(); err != nil {
					ev.Infra("write", "redis", "failed", fmt.Sprintf("failed to write schema upgrade response: %v", err))
				} else {
					ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
					if ttl <= 0 {
						ttl = 5 * time.Minute
					}
					if expireErr := k.rd.C().Expire(ctx, respStream, ttl).Err(); expireErr != nil {
						ev.Infra("error", "redis", "failed", fmt.Sprintf("failed to set response TTL: %v", expireErr))
					}
				}
				ev.Registration("success", fp, producerID, "success", fmt.Sprintf("completed: schema_upgrade schema=%s", req.SchemaName))
				if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
					ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack schema upgrade: %v", ackErr))
				}
			}
		}
	}
}
