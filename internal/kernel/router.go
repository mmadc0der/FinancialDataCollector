package kernel

import (
    "context"
    "encoding/json"
    "time"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/spill"
    "github.com/example/data-kernel/internal/logging"
    "github.com/example/data-kernel/internal/metrics"
)

type router struct {
    pg   *data.Postgres
    rd   *data.Redis
    sp   *spill.Writer
    replayer *spill.Replayer
    ack  func(ids ...string)
    pgCh chan pgMsg
    rdCh chan rdMsg
    publishEnabled bool
    // batching
    pgBatchSize int
    pgBatchWait time.Duration
    // ingest config (removed static producer/schema ids; derive if needed from payload in DB)
    prodID string
    schID  string
}

func newRouter(cfg *kernelcfg.Config, ack func(ids ...string)) (*router, error) {
    r := &router{publishEnabled: cfg.Redis.PublishEnabled, pgBatchSize: cfg.Postgres.BatchSize, pgBatchWait: time.Duration(cfg.Postgres.BatchMaxWaitMs) * time.Millisecond, ack: ack}
    if cfg.Postgres.Enabled {
        if pg, err := data.NewPostgres(cfg.Postgres); err == nil {
            r.pg = pg
            q := cfg.Postgres.QueueSize
            if q <= 0 { q = 1024 }
            r.pgCh = make(chan pgMsg, q)
            go r.pgWorkerBatch()
        } else {
            logging.Warn("postgres_init_error", logging.Err(err))
        }
    }
    if cfg.Redis.Enabled {
        if rd, err := data.NewRedis(cfg.Redis); err == nil {
            r.rd = rd
            q := cfg.Redis.QueueSize
            if q <= 0 { q = 2048 }
            r.rdCh = make(chan rdMsg, q)
            go r.rdWorker()
        } else {
            logging.Warn("redis_init_error", logging.Err(err))
        }
    }
    if cfg.Spill.Enabled {
        if sw, err := spill.NewWriter(cfg.Spill); err == nil {
            r.sp = sw
            r.replayer = spill.NewReplayer(cfg.Spill)
            go r.replayer.Start(context.Background(), r.pg)
        } else {
            logging.Warn("spill_init_error", logging.Err(err))
        }
    }
    return r, nil
}

func (r *router) close() {
    if r.sp != nil { _ = r.sp.Close() }
    if r.pg != nil { r.pg.Close() }
    if r.rd != nil { _ = r.rd.Close() }
}

// handleRedis enqueues a message coming from Redis for durable processing and optional re-publish
func (r *router) handleRedis(redisID string, env protocol.Envelope) {
    // Optional publish to Redis stream
    if r.rdCh != nil && r.publishEnabled {
        b, _ := json.Marshal(env)
        select {
        case r.rdCh <- rdMsg{ID: env.ID, Payload: b}:
        default:
        }
    }
    if r.pgCh != nil {
        select {
        case r.pgCh <- pgMsg{RedisID: redisID, Env: env}:
        default:
            // queue full; drop by policy (caller should DLQ), but here do nothing
        }
    } else {
        // If Postgres sink is disabled, ack immediately to avoid pending backlog
        if r.ack != nil { r.ack(redisID) }
    }
}

// routeRaw is no longer used for WS; kept for compatibility if needed.

type pgMsg struct { RedisID string; Env protocol.Envelope }

func (r *router) pgWorkerBatch() {
    buf := make([]pgMsg, 0, r.pgBatchSize)
    timer := time.NewTimer(r.pgBatchWait)
    defer timer.Stop()
    flush := func() {
        if len(buf) == 0 { return }
        // Build events array for ingest_events(jsonb)
        events := make([]map[string]any, 0, len(buf))
        redisIDs := make([]string, 0, len(buf))
        for _, m := range buf {
            var payload map[string]any
            _ = json.Unmarshal(m.Env.Data, &payload)
            // derive minimal tags from payload
            tags := make([]map[string]string, 0, 2)
            if s, ok := payload["source"].(string); ok && s != "" { tags = append(tags, map[string]string{"key":"core.source","value":s}) }
            if s, ok := payload["symbol"].(string); ok && s != "" { tags = append(tags, map[string]string{"key":"core.symbol","value":s}) }
            // build event object
            ev := map[string]any{
                "event_id": m.Env.ID,
                "ts": time.Unix(0, m.Env.TS).UTC().Format(time.RFC3339Nano),
                "subject_id": nil,
                "producer_id": r.producerID(),
                "schema_id": r.schemaID(),
                "payload": payload,
                "tags": tags,
            }
            events = append(events, ev)
            redisIDs = append(redisIDs, m.RedisID)
        }
        metrics.PGBatchSize.Observe(float64(len(events)))
        t0 := time.Now()
        err := r.pg.IngestEventsJSON(context.Background(), events)
        metrics.PGBatchDuration.Observe(time.Since(t0).Seconds())
        if err == nil {
            logging.Info("pg_batch_commit", logging.F("batch_size", len(events)), logging.F("duration_ms", time.Since(t0).Milliseconds()))
            if r.ack != nil { r.ack(redisIDs...) }
            buf = buf[:0]
            return
        }
        logging.Warn("pg_batch_error", logging.F("err", err.Error()), logging.F("batch_size", len(events)))
        // Retry a few times with exponential backoff
        const maxRetries = 3
        backoff := 200 * time.Millisecond
        for i := 1; i <= maxRetries; i++ {
            time.Sleep(backoff)
            t1 := time.Now()
            if e := r.pg.IngestEventsJSON(context.Background(), events); e == nil {
                logging.Info("pg_batch_commit_retry", logging.F("attempt", i), logging.F("batch_size", len(events)), logging.F("duration_ms", time.Since(t1).Milliseconds()))
                if r.ack != nil { r.ack(redisIDs...) }
                buf = buf[:0]
                return
            } else {
                logging.Warn("pg_batch_error_retry", logging.F("attempt", i), logging.F("err", e.Error()))
            }
            if backoff < 5*time.Second { backoff *= 2 }
        }
        // Batch failed after retries; try per-row fallback and track failures (still via ingest)
        failed := make([]pgMsg, 0, len(buf))
        succeededIDs := make([]string, 0, len(buf))
        for i, m := range buf {
            var payload map[string]any
            _ = json.Unmarshal(m.Env.Data, &payload)
            tags := make([]map[string]string, 0, 2)
            if s, ok := payload["source"].(string); ok && s != "" { tags = append(tags, map[string]string{"key":"core.source","value":s}) }
            if s, ok := payload["symbol"].(string); ok && s != "" { tags = append(tags, map[string]string{"key":"core.symbol","value":s}) }
            ev := []map[string]any{{
                "event_id": m.Env.ID,
                "ts": time.Unix(0, m.Env.TS).UTC().Format(time.RFC3339Nano),
                "subject_id": nil,
                "producer_id": r.producerID(),
                "schema_id": r.schemaID(),
                "payload": payload,
                "tags": tags,
            }}
            if e := r.pg.IngestEventsJSON(context.Background(), ev); e != nil {
                failed = append(failed, m)
            } else {
                succeededIDs = append(succeededIDs, redisIDs[i])
            }
        }
        if len(succeededIDs) > 0 && r.ack != nil { r.ack(succeededIDs...) }
        if len(failed) > 0 { logging.Warn("pg_fallback_failed_count", logging.F("count", len(failed))) }
        if len(failed) == 0 { buf = buf[:0]; return }
        // Spill failed ones if spill enabled
        if r.sp != nil {
            envs := make([]protocol.Envelope, 0, len(failed))
            ids := make([]string, 0, len(failed))
            for _, m := range failed { envs = append(envs, m.Env); ids = append(ids, m.RedisID) }
            if err := r.sp.WriteEnvelopes(envs); err == nil {
                logging.Info("spill_write", logging.F("count", len(ids)))
                if r.ack != nil { r.ack(ids...) }
                buf = buf[:0]
                return
            } else {
                logging.Error("spill_write_error", logging.F("err", err.Error()), logging.F("count", len(ids)))
            }
        }
        // Could not persist; keep buffer (will retry next cycle)
        logging.Warn("pg_persist_deferred", logging.F("buffer_len", len(buf)))
    }
    for {
        select {
        case m, ok := <-r.pgCh:
            if !ok { flush(); return }
            buf = append(buf, m)
            if len(buf) >= r.pgBatchSize { flush(); if !timer.Stop() { <-timer.C }; timer.Reset(r.pgBatchWait) }
        case <-timer.C:
            flush()
            timer.Reset(r.pgBatchWait)
        }
    }
}

type rdMsg struct {
    ID string
    Payload []byte
}

func (r *router) rdWorker() {
    for m := range r.rdCh {
        _ = r.rd.XAdd(context.Background(), m.ID, m.Payload)
    }
}

// helpers to provide producer/schema ids (may return nil to signal missing)
func (r *router) producerID() any {
    if r.prodID == "" { return nil }
    return r.prodID
}
func (r *router) schemaID() any {
    if r.schID == "" { return nil }
    return r.schID
}

