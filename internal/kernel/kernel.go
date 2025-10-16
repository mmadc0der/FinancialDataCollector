package kernel

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/logging"
    "github.com/example/data-kernel/internal/metrics"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/auth"
    "encoding/json"
    "strings"
    "errors"
    "github.com/redis/go-redis/v9"
    "bytes"
    "crypto/ed25519"
    "encoding/base64"
    ssh "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/sha3"
)

type Kernel struct {
	cfg *kernelcfg.Config
    rt  *router
    rd   *data.Redis
    pg   *data.Postgres
    au   *auth.Verifier
}

func NewKernel(configPath string) (*Kernel, error) {
	cfg, err := kernelcfg.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return &Kernel{cfg: cfg}, nil
}

func (k *Kernel) Start(ctx context.Context) error {
    stopLog := logging.Init(k.cfg.Logging)
    defer stopLog()
    logging.Info("kernel_start", logging.F("listen", k.cfg.Server.Listen))
    logging.Info("config_redis", logging.F("enabled", k.cfg.Redis.Enabled), logging.F("addr", k.cfg.Redis.Addr), logging.F("prefix", k.cfg.Redis.KeyPrefix), logging.F("stream", k.cfg.Redis.Stream), logging.F("group", k.cfg.Redis.ConsumerGroup))

    // Router handles durable persistence (Postgres-first, spill fallback) and optional publish
    r, err := newRouter(k.cfg, func(ids ...string) {
        if k.rd == nil || len(ids) == 0 { return }
        // best-effort ack with short timeout per batch
        _ = k.rd.Ack(context.Background(), ids...)
        metrics.RedisAckTotal.Add(float64(len(ids)))
    })
    if err != nil {
        return err
    }
    k.rt = r
    // Share Postgres instance from router to avoid duplicate initialization/migrations
    if r != nil { k.pg = r.pg }

    mux := http.NewServeMux()
    mux.Handle("/metrics", metrics.Handler())
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request){ w.WriteHeader(http.StatusOK); _,_ = w.Write([]byte("ok")) })
    mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request){ w.WriteHeader(http.StatusOK); _,_ = w.Write([]byte("ready")) })
    // Admin: pending/approve/revoke endpoints if enabled
    if k.cfg.Auth.Enabled {
        mux.HandleFunc("/admin/pending", k.handleListPending)
        mux.HandleFunc("/auth", k.handleAuthOverview)
        mux.HandleFunc("/admin/review", k.handleReview)
        mux.HandleFunc("/admin/approve", k.handleApprove) // backward compatibility
        mux.HandleFunc("/admin/revoke", k.handleRevokeToken)
    }
    server := &http.Server{Addr: k.cfg.Server.Listen, Handler: mux}

    // Auth verifier
    if k.cfg.Auth.Enabled {
        v, err := auth.NewVerifier(k.cfg.Auth, k.pg, k.rd)
        if err != nil { return err }
        k.au = v
        logging.Info("auth_verifier_initialized", logging.F("issuer", k.cfg.Auth.Issuer), logging.F("audience", k.cfg.Auth.Audience), logging.F("require_token", k.cfg.Auth.RequireToken))
    }

    // Start Redis consumer if enabled
    if k.cfg.Redis.Enabled && k.cfg.Redis.ConsumerEnabled {
        if rd, err := data.NewRedis(k.cfg.Redis); err == nil {
            k.rd = rd
            // best-effort create group
            _ = k.rd.EnsureGroup(ctx)
            logging.Info("redis_consumer_start", logging.F("stream", prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.Stream)), logging.F("group", k.cfg.Redis.ConsumerGroup))
            go k.consumeRedis(ctx)
            // registration stream consumer (fixed stream)
            go k.consumeRegister(ctx)
            // subject registration consumer (fixed stream)
            go k.consumeSubjectRegister(ctx)
            // token exchange consumer (fixed stream)
            go k.consumeTokenExchange(ctx)
        } else {
            logging.Warn("redis_consumer_init_error", logging.Err(err))
        }
    }

    go func() {
        <-ctx.Done()
        shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        // simple shutdown: stop HTTP, close router resources, close Redis
        _ = server.Shutdown(shutdownCtx)
        if k.rt != nil { k.rt.close() }
        if k.rd != nil { _ = k.rd.Close() }
        if k.pg != nil { k.pg.Close() }
    }()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}


// consumeRedis reads events from Redis Streams and enqueues to router
func (k *Kernel) consumeRedis(ctx context.Context) {
    consumer := fmt.Sprintf("%s-%d", "kernel", time.Now().UnixNano())
    count := k.cfg.Redis.ReadCount
    if count <= 0 { count = 100 }
    block := time.Duration(k.cfg.Redis.BlockMs) * time.Millisecond
    if block <= 0 { block = 5 * time.Second }
    dlq := prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.DLQStream)
    for ctx.Err() == nil {
        t0 := time.Now()
        streams, err := k.rd.ReadBatch(ctx, consumer, count, block)
        if err != nil {
            // backoff on errors
            logging.Warn("redis_read_error", logging.Err(err))
            time.Sleep(500 * time.Millisecond)
            continue
        }
        if len(streams) > 0 { metrics.RedisBatchDuration.Observe(time.Since(t0).Seconds()) }
        // Update stream length and pending approximations (best-effort)
        if k.rd != nil && k.rd.C() != nil {
            info, _ := k.rd.C().XInfoStream(ctx, prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.Stream)).Result()
            if info.Length > 0 { metrics.RedisStreamLenGauge.Set(float64(info.Length)) }
            // pending: XINFO GROUPS returns per-group pending
            groups, _ := k.rd.C().XInfoGroups(ctx, prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.Stream)).Result()
            for _, g := range groups {
                if strings.EqualFold(g.Name, k.cfg.Redis.ConsumerGroup) { metrics.RedisPendingGauge.Set(float64(g.Pending)) }
            }
        }
        for _, s := range streams {
            for _, m := range s.Messages {
                metrics.RedisReadTotal.Add(1)
                id, payload, token := data.DecodeMessage(m)
                if len(payload) == 0 {
                    _ = k.rd.ToDLQ(ctx, dlq, id, []byte("{}"), "empty_payload")
                    logging.Warn("redis_dlq_empty_payload", logging.F("id", id))
                    metrics.RedisDLQTotal.Add(1)
                    _ = k.rd.Ack(ctx, m.ID)
                    metrics.RedisAckTotal.Add(1)
                    continue
                }
                // Authenticate and capture producer/subject from token
                var producerID, subjectIDFromToken, jti string
                if k.au != nil && k.cfg.Auth.RequireToken {
                    if pid, sid, j, err := k.au.Verify(ctx, token); err != nil {
                        metrics.AuthDeniedTotal.Inc()
                        _ = k.rd.ToDLQ(ctx, dlq, id, payload, "unauthenticated")
                        logging.Warn("redis_auth_denied", logging.F("id", id), logging.Err(err))
                        _ = k.rd.Ack(ctx, m.ID)
                        metrics.RedisAckTotal.Add(1)
                        continue
                    } else { producerID, subjectIDFromToken, jti = pid, sid, j }
                }
                // If producer is disabled (deregistered), reject until re-registration
                if producerID != "" {
                    if disabled, err := k.pg.IsProducerDisabled(ctx, producerID); err == nil && disabled {
                        _ = k.rd.ToDLQ(ctx, dlq, id, payload, "producer_disabled")
                        logging.Warn("redis_producer_disabled", logging.F("id", id))
                        _ = k.rd.Ack(ctx, m.ID)
                        metrics.RedisAckTotal.Add(1)
                        continue
                    }
                }
                _ = jti // reserved for future gating
                // Parse lean event JSON from payload
                var ev struct{
                    EventID string `json:"event_id"`
                    TS      string `json:"ts"`
                    SubjectID string `json:"subject_id"`
                    Payload json.RawMessage `json:"payload"`
                    Tags    json.RawMessage `json:"tags"`
                }
                if err := json.Unmarshal(payload, &ev); err != nil || ev.EventID == "" || ev.TS == "" || ev.SubjectID == "" || len(ev.Payload) == 0 {
                    _ = k.rd.ToDLQ(ctx, dlq, id, payload, "bad_event_json")
                    logging.Warn("redis_dlq_bad_event_json", logging.F("id", id))
                    metrics.RedisDLQTotal.Add(1)
                    _ = k.rd.Ack(ctx, m.ID)
                    metrics.RedisAckTotal.Add(1)
                    continue
                }
                // if token has sid, enforce match
                if subjectIDFromToken != "" && !strings.EqualFold(subjectIDFromToken, ev.SubjectID) {
                    _ = k.rd.ToDLQ(ctx, dlq, id, payload, "subject_mismatch_token")
                    logging.Warn("redis_subject_mismatch", logging.F("id", id))
                    _ = k.rd.Ack(ctx, m.ID)
                    metrics.RedisAckTotal.Add(1)
                    continue
                }
                // Verify producer-subject binding
                if producerID != "" {
                    if ok, err := k.pg.CheckProducerSubject(ctx, producerID, ev.SubjectID); err != nil || !ok {
                        _ = k.rd.ToDLQ(ctx, dlq, id, payload, "producer_subject_forbidden")
                        logging.Warn("redis_producer_subject_forbidden", logging.F("id", id))
                        _ = k.rd.Ack(ctx, m.ID)
                        metrics.RedisAckTotal.Add(1)
                        continue
                    }
                }
                // Resolve schema via cache→DB
                var schemaID string
                if sid, ok := k.rd.SchemaCacheGet(ctx, ev.SubjectID); ok {
                    schemaID = sid
                } else if s, err := k.pg.GetCurrentSchemaID(ctx, ev.SubjectID); err == nil && s != "" {
                    schemaID = s
                    _ = k.rd.SchemaCacheSet(ctx, ev.SubjectID, s, time.Hour)
                }
                if schemaID == "" {
                    _ = k.rd.ToDLQ(ctx, dlq, id, payload, "missing_subject_schema")
                    logging.Warn("redis_missing_subject_schema", logging.F("id", id))
                    _ = k.rd.Ack(ctx, m.ID)
                    metrics.RedisAckTotal.Add(1)
                    continue
                }
                // route for durable handling; ack will be done after persistence via router callback
                k.rt.handleLeanEvent(m.ID, ev.EventID, ev.TS, ev.SubjectID, producerID, ev.Payload, ev.Tags, schemaID)
                logging.Debug("redis_event_enqueued", logging.F("id", id))
            }
        }
    }
}

func prefixed(prefix, key string) string {
    if prefix == "" { return key }
    return prefix + key
}

// envelope adaptation removed

// consumeSubjectRegister handles subject registration stream {token, payload:{subject_key, schema_id?, attrs?}}
func (k *Kernel) consumeSubjectRegister(ctx context.Context) {
    if k.rd == nil || k.pg == nil { return }
    stream := prefixed(k.cfg.Redis.KeyPrefix, "subject:register")
    if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
        _ = k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "$" ).Err()
    }
    consumer := fmt.Sprintf("%s-subreg-%d", "kernel", time.Now().UnixNano())
    for ctx.Err() == nil {
        res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second}).Result()
        if err != nil && !errors.Is(err, redis.Nil) { time.Sleep(200 * time.Millisecond); continue }
        if len(res) == 0 { continue }
        for _, s := range res {
            for _, m := range s.Messages {
                token, _ := m.Values["token"].(string)
                var producerID string
                if k.au != nil && k.cfg.Auth.RequireToken {
                    if pid, _, _, err := k.au.Verify(ctx, token); err == nil { producerID = pid } else { _ = k.rd.Ack(ctx, m.ID); continue }
                }
                payloadStr, _ := m.Values["payload"].(string)
                var req struct{ SubjectKey string `json:"subject_key"`; SchemaID string `json:"schema_id"`; Attrs json.RawMessage `json:"attrs"` }
                if payloadStr == "" || json.Unmarshal([]byte(payloadStr), &req) != nil || req.SubjectKey == "" { _ = k.rd.Ack(ctx, m.ID); continue }
                sid, err := k.pg.EnsureSubjectByKey(ctx, req.SubjectKey, req.Attrs)
                if err == nil && req.SchemaID != "" { _ = k.pg.SetCurrentSubjectSchema(ctx, sid, req.SchemaID); _ = k.rd.SchemaCacheSet(ctx, sid, req.SchemaID, time.Hour) }
                if producerID != "" { _ = k.pg.BindProducerSubject(ctx, producerID, sid) }
                // Respond on per-producer stream
                if producerID != "" {
                    _ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: prefixed(k.cfg.Redis.KeyPrefix, "subject:resp:"+producerID), MaxLen: k.cfg.Redis.MaxLenApprox, Approx: true, Values: map[string]any{"subject_id": sid}}).Err()
                }
                _ = k.rd.Ack(ctx, m.ID)
            }
        }
    }
}

// consumeTokenExchange handles token issuance/renewal via either approved pubkey signature or a valid existing token
func (k *Kernel) consumeTokenExchange(ctx context.Context) {
    if k.rd == nil || k.pg == nil || k.au == nil { return }
    stream := prefixed(k.cfg.Redis.KeyPrefix, "token:exchange")
    if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
        _ = k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "$" ).Err()
    }
    consumer := fmt.Sprintf("%s-token-%d", "kernel", time.Now().UnixNano())
    for ctx.Err() == nil {
        res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second}).Result()
        if err != nil && !errors.Is(err, redis.Nil) { time.Sleep(200 * time.Millisecond); continue }
        if len(res) == 0 { continue }
        for _, s := range res {
            for _, m := range s.Messages {
                // Path 1: renewal with existing token
                if tok, ok := m.Values["token"].(string); ok && tok != "" {
                    if pid, _, _, err := k.au.Verify(ctx, tok); err == nil {
                        if t, _, exp, ierr := k.au.Issue(ctx, pid, time.Hour, "exchange", ""); ierr == nil {
                            _ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: prefixed(k.cfg.Redis.KeyPrefix, "token:resp:"+pid), MaxLen: k.cfg.Redis.MaxLenApprox, Approx: true, Values: map[string]any{"producer_id": pid, "token": t, "exp": exp.UTC().Format(time.RFC3339Nano)}}).Err()
                        }
                    }
                    _ = k.rd.Ack(ctx, m.ID)
                    continue
                }
                // Path 2: new token via approved pubkey + signature
                pubkey, _ := m.Values["pubkey"].(string)
                payloadStr, _ := m.Values["payload"].(string)
                nonce, _ := m.Values["nonce"].(string)
                sigB64, _ := m.Values["sig"].(string)
                if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" { _ = k.rd.Ack(ctx, m.ID); continue }
                fp := sshFingerprint([]byte(pubkey))
                // verify signature as in registration
                parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
                if err != nil { _ = k.rd.Ack(ctx, m.ID); continue }
                if k.cfg.Auth.ProducerCertRequired && k.cfg.Auth.ProducerSSHCA != "" {
                    caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
                    if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) { parsedPub = cert.Key } else { parsedPub = nil }
                }
                okSig := false
                if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
                    if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
                        var tmp any
                        if json.Unmarshal([]byte(payloadStr), &tmp) == nil { if cb, e := json.Marshal(tmp); e == nil { payloadStr = string(cb) } }
                        msg := []byte(payloadStr + "." + nonce)
                        sum := sha3.Sum512(msg)
                        sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
                        if decErr != nil { sigBytes, _ = base64.StdEncoding.DecodeString(sigB64) }
                        if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, sum[:], sigBytes) { okSig = true }
                    }
                }
                if !okSig { _ = k.rd.Ack(ctx, m.ID); continue }
                status, producerID, err := k.pg.GetKeyStatus(ctx, fp)
                if err != nil {
                    logging.Info("token_exchange_status_check_error", logging.F("fingerprint", fp), logging.Err(err))
                    _ = k.rd.Ack(ctx, m.ID)
                    continue
                }
                if status == "" {
                    logging.Info("token_exchange_unknown_key", logging.F("fingerprint", fp))
                    _ = k.rd.Ack(ctx, m.ID)
                    continue
                }
                if status != "approved" {
                    logging.Info("token_exchange_key_not_approved", logging.F("fingerprint", fp), logging.F("status", status))
                    _ = k.rd.Ack(ctx, m.ID)
                    continue
                }
                if producerID == nil || *producerID == "" {
                    logging.Info("token_exchange_no_producer", logging.F("fingerprint", fp))
                    _ = k.rd.Ack(ctx, m.ID)
                    continue
                }
                if t, _, exp, ierr := k.au.Issue(ctx, *producerID, time.Hour, "exchange", fp); ierr == nil {
                    _ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: prefixed(k.cfg.Redis.KeyPrefix, "token:resp:"+*producerID), MaxLen: k.cfg.Redis.MaxLenApprox, Approx: true, Values: map[string]any{"fingerprint": fp, "producer_id": *producerID, "token": t, "exp": exp.UTC().Format(time.RFC3339Nano)}}).Err()
                } else {
                    logging.Info("token_exchange_issue_error", logging.F("fingerprint", fp), logging.Err(ierr))
                }
                _ = k.rd.Ack(ctx, m.ID)
            }
        }
    }
}









