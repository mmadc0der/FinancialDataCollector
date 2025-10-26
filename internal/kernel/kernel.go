package kernel

import (
	"fmt"
	"net/http"

	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"context"
	"sync"
	"time"

	"github.com/example/data-kernel/internal/auth"
	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
	"github.com/example/data-kernel/internal/logging"
	"github.com/example/data-kernel/internal/metrics"
	"github.com/redis/go-redis/v9"
	ssh "golang.org/x/crypto/ssh"
)

// Context pool for reducing context creation overhead
var contextPool = sync.Pool{
	New: func() interface{} {
		return context.Background()
	},
}

// GetContext gets a context from the pool or creates a new one
func getContext() context.Context {
	return contextPool.Get().(context.Context)
}

// PutContext returns a context to the pool
func putContext(ctx context.Context) {
	// Only pool background contexts to avoid issues with cancelled contexts
	if ctx == context.Background() {
		contextPool.Put(ctx)
	}
}

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
    logging.Info("config_redis", logging.F("addr", k.cfg.Redis.Addr), logging.F("prefix", k.cfg.Redis.KeyPrefix), logging.F("stream", k.cfg.Redis.Stream), logging.F("group", k.cfg.Redis.ConsumerGroup))

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
    // Auth endpoints (mandatory)
    mux.HandleFunc("/auth", k.handleListPending)
    mux.HandleFunc("/auth/review", k.handleReview)
    mux.HandleFunc("/auth/revoke", k.handleRevokeToken)
    server := &http.Server{Addr: k.cfg.Server.Listen, Handler: mux}

    // Auth verifier (mandatory)
    v, err := auth.NewVerifier(k.cfg.Auth, k.pg, k.rd)
    if err != nil { return err }
    k.au = v
    logging.Info("auth_verifier_initialized", logging.F("issuer", k.cfg.Auth.Issuer), logging.F("audience", k.cfg.Auth.Audience))

    // Start Redis consumer (mandatory)
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
                globalMetricsBatcher.IncRedisRead()
                id, payload, token := data.DecodeMessage(m)
                if len(payload) == 0 {
                    _ = k.rd.ToDLQ(ctx, dlq, id, []byte("{}"), "empty_payload")
                    logging.Warn("redis_dlq_empty_payload", logging.F("id", id))
                    globalMetricsBatcher.IncRedisDLQ()
                    _ = k.rd.Ack(ctx, m.ID)
                    globalMetricsBatcher.IncRedisAck()
                    continue
                }
                // Authenticate and capture producer/subject from token
                var producerID, subjectIDFromToken, jti string
                {
                    if pid, sid, j, err := k.au.Verify(ctx, token); err != nil {
                        globalMetricsBatcher.IncAuthDenied()
                        _ = k.rd.ToDLQ(ctx, dlq, id, payload, "unauthenticated")
                        logging.Warn("redis_auth_denied", logging.F("id", id), logging.F("redis_id", m.ID), logging.Err(err))
                        if ackErr := k.rd.Ack(ctx, m.ID); ackErr != nil {
                            logging.Error("redis_ack_failed", logging.F("redis_id", m.ID), logging.Err(ackErr))
                        } else {
                            globalMetricsBatcher.IncRedisAck()
                        }
                        continue
                    } else { producerID, subjectIDFromToken, jti = pid, sid, j }
                }
                // If producer is disabled (deregistered), reject until re-registration
                if producerID != "" {
                    if disabled, err := k.pg.IsProducerDisabled(ctx, producerID); err == nil && disabled {
                        _ = k.rd.ToDLQ(ctx, dlq, id, payload, "producer_disabled")
                        logging.Warn("redis_producer_disabled", logging.F("id", id))
                        _ = k.rd.Ack(ctx, m.ID)
                        globalMetricsBatcher.IncRedisAck()
                        continue
                    }
                }
                _ = jti // reserved for future gating
                // Parse lean event JSON from payload
                var ev struct{
                    EventID   string          `json:"event_id"`
                    TS        string          `json:"ts"`
                    SubjectID string          `json:"subject_id"`
                    Payload   json.RawMessage `json:"payload"`
                    Tags      json.RawMessage `json:"tags"`
                }
                if err := json.Unmarshal(payload, &ev); err != nil || ev.EventID == "" || ev.TS == "" || ev.SubjectID == "" || len(ev.Payload) == 0 {
                    _ = k.rd.ToDLQ(ctx, dlq, id, payload, "bad_event_json")
                    logging.Warn("redis_dlq_bad_event_json", logging.F("id", id))
                    globalMetricsBatcher.IncRedisDLQ()
                    _ = k.rd.Ack(ctx, m.ID)
                    globalMetricsBatcher.IncRedisAck()
                    continue
                }
                // if token has sid, enforce match
                if subjectIDFromToken != "" && !strings.EqualFold(subjectIDFromToken, ev.SubjectID) {
                    _ = k.rd.ToDLQ(ctx, dlq, id, payload, "subject_mismatch_token")
                    logging.Warn("redis_subject_mismatch", logging.F("id", id))
                    _ = k.rd.Ack(ctx, m.ID)
                    globalMetricsBatcher.IncRedisAck()
                    continue
                }
                // Verify producer-subject binding
                if producerID != "" {
                    if ok, err := k.pg.CheckProducerSubject(ctx, producerID, ev.SubjectID); err != nil || !ok {
                        _ = k.rd.ToDLQ(ctx, dlq, id, payload, "producer_subject_forbidden")
                        logging.Warn("redis_producer_subject_forbidden", logging.F("id", id))
                        _ = k.rd.Ack(ctx, m.ID)
                        globalMetricsBatcher.IncRedisAck()
                        continue
                    }
                }
                // Resolve schema via Redis cache; on miss, fallback to Postgres and backfill cache
                var schemaID string
                if sid, ok := k.rd.SchemaCacheGet(ctx, ev.SubjectID); ok {
                    schemaID = sid
                } else {
                    // Fallback: query Postgres for current schema_id and cache it
                    if k.pg != nil {
                        if sid, err := k.pg.GetCurrentSchemaID(ctx, ev.SubjectID); err == nil && sid != "" {
                            schemaID = sid
                            ttl := time.Duration(k.cfg.Performance.SchemaCacheTTLSeconds) * time.Second
                            if ttl <= 0 { ttl = time.Hour }
                            _ = k.rd.SchemaCacheSet(ctx, ev.SubjectID, schemaID, ttl)
                            logging.Info("schema_cache_backfilled", logging.F("subject_id", ev.SubjectID), logging.F("schema_id", schemaID))
                        }
                    }
                    if schemaID == "" {
                        _ = k.rd.ToDLQ(ctx, dlq, id, payload, "schema_missing")
                        logging.Warn("redis_schema_missing", logging.F("subject_id", ev.SubjectID), logging.F("id", id))
                        _ = k.rd.Ack(ctx, m.ID)
                        globalMetricsBatcher.IncRedisAck()
                        continue
                    }
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

// coalesceJSON returns raw JSON string or empty object if nil/empty.
func coalesceJSON(b json.RawMessage) string {
    if len(b) == 0 || string(b) == "" { return "{}" }
    return string(b)
}

// envelope adaptation removed

// sendSubjectResponse sends a response message to per-producer subject response stream with TTL
func (k *Kernel) sendSubjectResponse(ctx context.Context, producerID string, values map[string]any) {
    if k == nil || k.rd == nil || k.rd.C() == nil || producerID == "" { return }
    respStream := prefixed(k.cfg.Redis.KeyPrefix, "subject:resp:"+producerID)
    _ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: respStream, Values: values}).Err()
    ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
    if ttl <= 0 { ttl = 5 * time.Minute }
    _ = k.rd.C().Expire(ctx, respStream, ttl).Err()
}

// consumeSubjectRegister handles subject registration stream signed by SSH pubkey
// Message fields: pubkey, payload (canonical JSON), nonce, sig
// Payload supports ops: set_current (default) and upgrade_auto
func (k *Kernel) consumeSubjectRegister(ctx context.Context) {
    if k.rd == nil || k.pg == nil { return }
    stream := prefixed(k.cfg.Redis.KeyPrefix, "subject:register")
    if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
        _ = k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "0-0" ).Err()
    }
    consumer := fmt.Sprintf("%s-subreg-%d", "kernel", time.Now().UnixNano())
    for ctx.Err() == nil {
        res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second}).Result()
        if err != nil && !errors.Is(err, redis.Nil) { time.Sleep(200 * time.Millisecond); continue }
        if len(res) == 0 { continue }
        for _, s := range res {
            for _, m := range s.Messages {
                pubkey, _ := m.Values["pubkey"].(string)
                payloadStr, _ := m.Values["payload"].(string)
                nonce, _ := m.Values["nonce"].(string)
                sigB64, _ := m.Values["sig"].(string)
                // Initial request log for visibility
                fp0 := ""
                if pubkey != "" { fp0 = sshFingerprint([]byte(pubkey)) }
                logging.Info("subject_register_request", logging.F("id", m.ID), logging.F("fingerprint", fp0), logging.F("nonce", nonce), logging.F("payload_len", len(payloadStr)))
                if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" {
                    logging.Warn("subject_register_missing_signature", logging.F("id", m.ID))
                    _ = k.rd.Ack(ctx, m.ID)
                    continue
                }
                // Verify signature and CA; ensure key approved; get producer_id
                producerID := ""
                {
                    fp := sshFingerprint([]byte(pubkey))
                    parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
                    if err != nil { _ = k.rd.Ack(ctx, m.ID); continue }
                if k.cfg.Auth.ProducerSSHCA != "" {
                        caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
                        if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) { parsedPub = cert.Key } else { parsedPub = nil }
                    }
                    okSig := false
                    if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
                        if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
                            var tmp any
                            if json.Unmarshal([]byte(payloadStr), &tmp) == nil { if cb, e := json.Marshal(tmp); e == nil { payloadStr = string(cb) } }
                            // Ed25519-only: verify raw signature over canonical bytes without prehash
                            msg := []byte(payloadStr + "." + nonce)
                            sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
                            if decErr != nil { sigBytes, _ = base64.StdEncoding.DecodeString(sigB64) }
                            if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) { okSig = true }
                        }
                    }
                    if !okSig {
                        logging.Warn("subject_register_bad_signature", logging.F("id", m.ID), logging.F("fingerprint", fp), logging.F("nonce", nonce))
                        // best-effort send error response if producer is known
                        if status, pidPtr, _ := k.pg.GetKeyStatus(ctx, fp); pidPtr != nil && *pidPtr != "" {
                            _ = status // status not used for this error
                            k.sendSubjectResponse(ctx, *pidPtr, map[string]any{"error": "invalid_sig", "reason": "signature_verification_failed"})
                        }
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                    status, pidPtr, err := k.pg.GetKeyStatus(ctx, fp)
                    if err != nil || status != "approved" || pidPtr == nil || *pidPtr == "" {
                        logging.Warn("subject_register_key_not_approved", logging.F("id", m.ID), logging.F("fingerprint", fp), logging.F("status", status))
                        if pidPtr != nil && *pidPtr != "" {
                            k.sendSubjectResponse(ctx, *pidPtr, map[string]any{"error": "key_not_approved", "status": status})
                        }
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                    producerID = *pidPtr
                    // replay protection - check after we have producer ID
                    if k.rd != nil && k.rd.C() != nil {
                        // Use per-producer SET to track nonces: key fdc:subject:nonce:<producer_id>
                        setKey := prefixed(k.cfg.Redis.KeyPrefix, "subject:nonce:"+producerID)
                        // SADD returns 1 if newly added, 0 if existed → treat 0 as replay
                        added, err := k.rd.C().SAdd(ctx, setKey, nonce).Result()
                        if err != nil {
                            logging.Warn("subject_register_nonce_guard_error", logging.F("id", m.ID), logging.F("producer_id", producerID), logging.F("nonce", nonce), logging.Err(err))
                        } else if added == 0 {
                            logging.Warn("subject_register_replay", logging.F("id", m.ID), logging.F("producer_id", producerID), logging.F("nonce", nonce))
                            k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "replay"})
                            _ = k.rd.Ack(ctx, m.ID)
                            continue
                        } else {
                            // ensure TTL exists (best-effort)
                            _ = k.rd.C().Expire(ctx, setKey, 10*time.Minute).Err()
                        }
                    }
                    if !k.checkRateLimit(ctx, producerID) {
                        // best-effort notify client
                        k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "rate_limited"})
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                }
                var req struct{
                    Op           string          `json:"op"`
                    SubjectKey   string          `json:"subject_key"`
                    SchemaName   string          `json:"schema_name"`
                    SchemaBody   json.RawMessage `json:"schema_body"`
                    SchemaDelta  json.RawMessage `json:"schema_delta"`
                    Attrs        json.RawMessage `json:"attrs"`
                    AttrsDelta   json.RawMessage `json:"attrs_delta"`
                }
                if payloadStr == "" || json.Unmarshal([]byte(payloadStr), &req) != nil || req.SubjectKey == "" { 
                    logging.Warn("subject_register_invalid_payload", logging.F("id", m.ID), logging.F("payload", payloadStr))
                    if producerID != "" { k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload"}) }
                    _ = k.rd.Ack(ctx, m.ID)
                    continue 
                }
                // Strict op validation before any DB calls
                switch strings.ToLower(strings.TrimSpace(req.Op)) {
                case "register":
                    if strings.TrimSpace(req.SchemaName) == "" || len(req.SchemaBody) == 0 || strings.TrimSpace(string(req.SchemaBody)) == "" {
                        logging.Warn("subject_register_validation_failed", logging.F("id", m.ID), logging.F("reason", "missing_schema_name_or_body"))
                        if producerID != "" { k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload", "details": "register requires schema_name and schema_body"}) }
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                    if len(strings.TrimSpace(string(req.SchemaDelta))) > 0 || len(strings.TrimSpace(string(req.AttrsDelta))) > 0 {
                        if producerID != "" { k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload", "details": "delta fields not allowed for register"}) }
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                case "upgrade":
                    if strings.TrimSpace(req.SchemaName) == "" || len(strings.TrimSpace(string(req.SchemaDelta))) == 0 {
                        logging.Warn("subject_register_validation_failed", logging.F("id", m.ID), logging.F("reason", "missing_schema_name_or_delta"))
                        if producerID != "" { k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload", "details": "upgrade requires schema_name and schema_delta"}) }
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                    if len(strings.TrimSpace(string(req.SchemaBody))) > 0 {
                        if producerID != "" { k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "invalid_payload", "details": "schema_body not allowed for upgrade"}) }
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                default:
                    logging.Warn("subject_register_unknown_op", logging.F("id", m.ID), logging.F("op", req.Op))
                    if producerID != "" { k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "unknown_op", "op": req.Op}) }
                    _ = k.rd.Ack(ctx, m.ID)
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
                        logging.Warn("subject_register_upgrade_error", logging.F("id", m.ID), logging.Err(err))
                        if producerID != "" { k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "upgrade_failed"}) }
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                case "register":
                    var unchanged bool
                    sid, schemaID, schemaVersion, unchanged, err = k.pg.BootstrapSubjectWithSchema(ctx, req.SubjectKey, req.SchemaName, []byte(coalesceJSON(req.SchemaBody)), []byte(coalesceJSON(req.Attrs)))
                    _ = unchanged
                    schemaName = req.SchemaName
                    if err != nil {
                        logging.Warn("subject_register_register_error", logging.F("id", m.ID), logging.Err(err))
                        if producerID != "" { k.sendSubjectResponse(ctx, producerID, map[string]any{"error": "register_failed"}) }
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                }
                // Set current schema and cache
                if sid != "" && schemaID != "" {
                    _ = k.pg.SetCurrentSubjectSchema(ctx, sid, schemaID)
                    _ = k.rd.SchemaCacheSet(ctx, sid, schemaID, time.Hour)
                    if producerID != "" { _ = k.pg.BindProducerSubject(ctx, producerID, sid) }
                }
                // Respond on per-producer stream
                if producerID != "" {
                    resp := map[string]any{"status":"ok", "producer_id": producerID, "subject_id": sid, "schema_id": schemaID}
                    if schemaName != "" { resp["schema_name"] = schemaName }
                    if schemaVersion > 0 { resp["schema_version"] = schemaVersion }
                    k.sendSubjectResponse(ctx, producerID, resp)
                    logging.Info("subject_register_success",
                        logging.F("producer_id", producerID),
                        logging.F("subject_id", sid),
                        logging.F("subject_key", req.SubjectKey),
                        logging.F("attrs", coalesceJSON(req.Attrs)),
                        logging.F("schema_id", schemaID),
                        logging.F("schema_name", schemaName),
                        logging.F("schema_version", schemaVersion),
                    )
                } else {
                    logging.Warn("subject_register_no_producer", logging.F("id", m.ID))
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
        _ = k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "0-0" ).Err()
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
                        // Deny renewal for disabled producers
                        if disabled, derr := k.pg.IsProducerDisabled(ctx, pid); derr == nil && disabled {
                            _ = k.rd.Ack(ctx, m.ID)
                            continue
                        }
                        if t, _, exp, ierr := k.au.Issue(ctx, pid, time.Hour, "exchange", ""); ierr == nil {
                            respStream := prefixed(k.cfg.Redis.KeyPrefix, "token:resp:"+pid)
                            _ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: respStream, Values: map[string]any{"producer_id": pid, "token": t, "exp": exp.UTC().Format(time.RFC3339Nano)}}).Err()
                            // Set TTL on token response stream to prevent accumulation of stale responses
                            ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
                            if ttl <= 0 { ttl = 5 * time.Minute }
                            _ = k.rd.C().Expire(ctx, respStream, ttl).Err()
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
                if k.cfg.Auth.ProducerSSHCA != "" {
                    caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
                    if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) { parsedPub = cert.Key } else { parsedPub = nil }
                }
                okSig := false
                if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
                    if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
                        var tmp any
                        if json.Unmarshal([]byte(payloadStr), &tmp) == nil { if cb, e := json.Marshal(tmp); e == nil { payloadStr = string(cb) } }
                        // Ed25519-only: verify raw signature over canonical bytes without prehash
                        msg := []byte(payloadStr + "." + nonce)
                        sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
                        if decErr != nil { sigBytes, _ = base64.StdEncoding.DecodeString(sigB64) }
                        if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) { okSig = true }
                    }
                }
                if !okSig { _ = k.rd.Ack(ctx, m.ID); continue }
                status, producerID, err := k.pg.GetKeyStatus(ctx, fp)
                if err != nil {
                    logging.Error("token_exchange_status_check_error", logging.F("fingerprint", fp), logging.Err(err))
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
                // Deny token issue when producer disabled
                if disabled, derr := k.pg.IsProducerDisabled(ctx, *producerID); derr == nil && disabled {
                    _ = k.rd.Ack(ctx, m.ID)
                    continue
                }

                // Rate limiting check for token exchange
                if !k.checkRateLimit(ctx, *producerID) {
                    _ = k.rd.Ack(ctx, m.ID)
                    continue // silent drop for rate limited requests
                }

                if t, jti, exp, ierr := k.au.Issue(ctx, *producerID, time.Hour, "exchange", fp); ierr == nil {
                    logging.Info("token_exchange_issued", logging.F("fingerprint", fp), logging.F("producer_id", *producerID), logging.F("jti", jti))
                    respStream := prefixed(k.cfg.Redis.KeyPrefix, "token:resp:"+*producerID)
                    err := k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: respStream, Values: map[string]any{"fingerprint": fp, "producer_id": *producerID, "token": t, "exp": exp.UTC().Format(time.RFC3339Nano)}}).Err()
                    if err != nil {
                        logging.Error("token_exchange_response_error", logging.F("jti", jti), logging.F("producer_id", *producerID), logging.Err(err))
                    } else {
                        // Set TTL on token response stream to prevent accumulation of stale responses
                        ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
                        if ttl <= 0 { ttl = 5 * time.Minute }
                        if expireErr := k.rd.C().Expire(ctx, respStream, ttl).Err(); expireErr != nil {
                            logging.Warn("token_resp_ttl_error", logging.F("jti", jti), logging.F("producer_id", *producerID), logging.Err(expireErr))
                        }
                    }
                } else {
                    logging.Info("token_exchange_issue_error", logging.F("fingerprint", fp), logging.Err(ierr))
                }
                _ = k.rd.Ack(ctx, m.ID)
            }
        }
    }
}

// consumeSchemaUpgrade handles dedicated schema upgrade requests signed by producer key
// Stream: prefix+"schema:upgrade"; fields: pubkey, payload, nonce, sig
// Payload: { subject_key, schema_name, schema_body, attrs? }
func (k *Kernel) consumeSchemaUpgrade(ctx context.Context) {
    if k.rd == nil || k.pg == nil { return }
    stream := prefixed(k.cfg.Redis.KeyPrefix, "schema:upgrade")
    if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
        _ = k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "0-0" ).Err()
    }
    consumer := fmt.Sprintf("%s-schup-%d", "kernel", time.Now().UnixNano())
    for ctx.Err() == nil {
        res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second}).Result()
        if err != nil && !errors.Is(err, redis.Nil) { time.Sleep(200 * time.Millisecond); continue }
        if len(res) == 0 { continue }
        for _, s := range res {
            for _, m := range s.Messages {
                pubkey, _ := m.Values["pubkey"].(string)
                payloadStr, _ := m.Values["payload"].(string)
                nonce, _ := m.Values["nonce"].(string)
                sigB64, _ := m.Values["sig"].(string)
                if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" { _ = k.rd.Ack(ctx, m.ID); continue }
                // Verify signature and approved producer
                fp := sshFingerprint([]byte(pubkey))
                parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
                if err != nil { _ = k.rd.Ack(ctx, m.ID); continue }
                if k.cfg.Auth.ProducerSSHCA != "" {
                    caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
                    if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) { parsedPub = cert.Key } else { parsedPub = nil }
                }
                okSig := false
                if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
                    if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
                        var tmp any
                        if json.Unmarshal([]byte(payloadStr), &tmp) == nil { if cb, e := json.Marshal(tmp); e == nil { payloadStr = string(cb) } }
                        // Ed25519-only: verify raw signature over canonical bytes without prehash
                        msg := []byte(payloadStr + "." + nonce)
                        sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
                        if decErr != nil { sigBytes, _ = base64.StdEncoding.DecodeString(sigB64) }
                        if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) { okSig = true }
                    }
                }
                if !okSig { _ = k.rd.Ack(ctx, m.ID); continue }
                // replay protection
                if k.rd != nil && k.rd.C() != nil {
                    ok, err := k.rd.C().SetNX(ctx, prefixed(k.cfg.Redis.KeyPrefix, "subject:nonce:"+fp+":"+nonce), "1", 5*time.Minute).Result()
                    if err != nil {
                        logging.Warn("schema_upgrade_nonce_guard_error", logging.F("id", m.ID), logging.F("fingerprint", fp), logging.F("nonce", nonce), logging.Err(err))
                        // allow on error
                    } else if !ok {
                        logging.Warn("schema_upgrade_replay", logging.F("id", m.ID), logging.F("fingerprint", fp), logging.F("nonce", nonce))
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                }
                status, pidPtr, err := k.pg.GetKeyStatus(ctx, fp)
                if err != nil || status != "approved" || pidPtr == nil || *pidPtr == "" { _ = k.rd.Ack(ctx, m.ID); continue }
                producerID := *pidPtr
                if !k.checkRateLimit(ctx, producerID) { _ = k.rd.Ack(ctx, m.ID); continue }

                // Parse payload
                var req struct{
                    SubjectKey string          `json:"subject_key"`
                    SchemaName string          `json:"schema_name"`
                    SchemaBody json.RawMessage `json:"schema_body"`
                    Attrs      json.RawMessage `json:"attrs"`
                }
                if payloadStr == "" || json.Unmarshal([]byte(payloadStr), &req) != nil || req.SubjectKey == "" || req.SchemaName == "" || len(req.SchemaBody) == 0 {
                    logging.Warn("schema_upgrade_invalid_payload", logging.F("id", m.ID))
                    _ = k.rd.Ack(ctx, m.ID)
                    continue
                }
                // Perform atomic upgrade (auto-assign next version)
                sid, schemaID, version, uerr := k.pg.UpgradeSubjectSchemaAuto(ctx, req.SubjectKey, req.SchemaName, []byte(coalesceJSON(req.SchemaBody)), []byte(coalesceJSON(req.Attrs)), true)
                if uerr != nil { logging.Warn("schema_upgrade_error", logging.F("id", m.ID), logging.Err(uerr)); _ = k.rd.Ack(ctx, m.ID); continue }
                _ = k.rd.SchemaCacheSet(ctx, sid, schemaID, time.Hour)
                _ = k.pg.BindProducerSubject(ctx, producerID, sid)
                // Respond via subject:resp:<producer_id>
                resp := map[string]any{"subject_id": sid, "schema_id": schemaID, "schema_name": req.SchemaName, "schema_version": version}
                respStream := prefixed(k.cfg.Redis.KeyPrefix, "subject:resp:"+producerID)
                _ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: respStream, Values: resp}).Err()
                ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
                if ttl <= 0 { ttl = 5 * time.Minute }
                _ = k.rd.C().Expire(ctx, respStream, ttl).Err()
                logging.Info("schema_upgrade_success", logging.F("producer_id", producerID), logging.F("subject_id", sid), logging.F("schema_id", schemaID), logging.F("schema_name", req.SchemaName), logging.F("schema_version", version))
                _ = k.rd.Ack(ctx, m.ID)
            }
        }
    }
}









