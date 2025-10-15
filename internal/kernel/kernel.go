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
    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/auth"
    "encoding/json"
    "strings"
)

type Kernel struct {
	cfg *kernelcfg.Config
    rt  *router
    rd   *data.Redis
    pg   *data.Postgres
    au   *auth.Verifier
    // test seams for admin handlers
    approveProducerKey func(ctx context.Context, fingerprint, name, schemaID, reviewer, notes string) (string, error)
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
    logging.Info("config_redis", logging.F("enabled", k.cfg.Redis.Enabled), logging.F("addr", k.cfg.Redis.Addr), logging.F("prefix", k.cfg.Redis.KeyPrefix), logging.F("stream", k.cfg.Redis.Stream), logging.F("register_stream", k.cfg.Redis.RegisterStream), logging.F("group", k.cfg.Redis.ConsumerGroup))

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
        mux.HandleFunc("/admin/approve", k.handleApprove)
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
            // registration stream consumer (separate goroutine)
            go k.consumeRegister(ctx)
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
                id, payload, token := data.DecodeEnvelope(m)
                if len(payload) == 0 {
                    _ = k.rd.ToDLQ(ctx, dlq, id, []byte("{}"), "empty_payload")
                    logging.Warn("redis_dlq_empty_payload", logging.F("id", id))
                    metrics.RedisDLQTotal.Add(1)
                    _ = k.rd.Ack(ctx, m.ID)
                    metrics.RedisAckTotal.Add(1)
                    continue
                }
                // Authenticate producer if required
                if k.au != nil && k.cfg.Auth.RequireToken {
                    if _, _, _, err := k.au.Verify(ctx, token); err != nil {
                        metrics.AuthDeniedTotal.Inc()
                        _ = k.rd.ToDLQ(ctx, dlq, id, payload, "unauthenticated")
                        logging.Warn("redis_auth_denied", logging.F("id", id), logging.Err(err))
                        _ = k.rd.Ack(ctx, m.ID)
                        metrics.RedisAckTotal.Add(1)
                        continue
                    }
                }
                // validate envelope before routing
                var env struct{ Version string `json:"version"`; Type string `json:"type"`; ID string `json:"id"`; TS int64 `json:"ts"`; Data json.RawMessage `json:"data"` }
                if err := json.Unmarshal(payload, &env); err != nil || env.ID == "" || env.Version == "" || env.TS == 0 {
                    _ = k.rd.ToDLQ(ctx, dlq, id, payload, "bad_envelope")
                    logging.Warn("redis_dlq_bad_envelope", logging.F("id", id))
                    metrics.RedisDLQTotal.Add(1)
                    _ = k.rd.Ack(ctx, m.ID)
                    metrics.RedisAckTotal.Add(1)
                    continue
                }
                // handle control plane ops (e.g., ensure_schema_subject)
                if env.Type == "control" {
                    _ = k.rd.Ack(ctx, m.ID)
                    metrics.RedisAckTotal.Add(1)
                    _ = k.handleControl(ctx, m.ID, protocolEnvelopeLite{Version: env.Version, Type: env.Type, ID: env.ID, TS: env.TS, Data: env.Data}, payload)
                    logging.Info("redis_control_handled", logging.F("id", id))
                    continue
                }
                // route for durable handling; ack will be done after persistence via router callback
                k.rt.handleRedis(m.ID, protocolEnvelope(env))
                logging.Debug("redis_event_enqueued", logging.F("id", id))
            }
        }
    }
}

func prefixed(prefix, key string) string {
    if prefix == "" { return key }
    return prefix + key
}

// protocolEnvelope adapts a lightweight parsed struct into protocol.Envelope
func protocolEnvelope(e struct{ Version string `json:"version"`; Type string `json:"type"`; ID string `json:"id"`; TS int64 `json:"ts"`; Data json.RawMessage `json:"data"` }) protocol.Envelope {
    return protocol.Envelope{Version: e.Version, Type: e.Type, ID: e.ID, TS: e.TS, Data: e.Data}
}









