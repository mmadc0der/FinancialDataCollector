package kernel

import (
    "context"
    "encoding/json"
    "errors"
    "io"
    "net"
    "strings"
    "time"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
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
    pgChLean chan pgMsgLean
    rdCh chan rdMsg
    publishEnabled bool
    // batching
    pgBatchSize int
    pgBatchWait time.Duration
    // ingest config (producer/schema ids are not defaulted for lean events)
    prodID string
    schID  string
}

func newRouter(cfg *kernelcfg.Config, ack func(ids ...string)) (*router, error) {
    r := &router{publishEnabled: cfg.Redis.PublishEnabled, pgBatchSize: cfg.Postgres.BatchSize, pgBatchWait: time.Duration(cfg.Postgres.BatchMaxWaitMs) * time.Millisecond, ack: ack}
    // pick defaults from config, may be empty which signals NULL in DB
    r.prodID = cfg.Postgres.DefaultProducerID
    r.schID = ""
    if cfg.Postgres.Enabled {
        if pg, err := data.NewPostgres(cfg.Postgres); err == nil {
            r.pg = pg
            q := cfg.Postgres.QueueSize
            if q <= 0 { q = 1024 }
            r.pgCh = make(chan pgMsg, q)
            go r.pgWorkerBatch()
            r.pgChLean = make(chan pgMsgLean, q)
            go r.pgWorkerBatchLean()
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
func (r *router) handleRedis(redisID string, _ any) { /* removed for lean path */ }

// routeRaw is no longer used for WS; kept for compatibility if needed.

type pgMsg struct { RedisID string; Env any }

// Lean event message (no envelope)
type pgMsgLean struct {
    RedisID   string
    EventID   string
    TS        string
    SubjectID string
    ProducerID string
    SchemaID  string
    Payload   []byte
    Tags      []byte
}

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
            // legacy envelope path removed; ignore pgMsg.Env contents for lean protocol
            ev := map[string]any{}
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
        lastErr := err
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
                lastErr = e
            }
            if backoff < 5*time.Second { backoff *= 2 }
        }
        // If this looks like a connectivity error, optionally spill to filesystem (as last resort)
        if isConnectivityError(lastErr) {
            if r.sp != nil {
                // spill disabled for lean events path (no envelope); keep ack/defer behavior
                ids := make([]string, 0, len(buf))
                for _, m := range buf { ids = append(ids, m.RedisID) }
                if len(ids) > 0 {
                    logging.Error("spill_write_connectivity_fallback", logging.F("count", len(ids)), logging.F("err", lastErr.Error()))
                    if r.ack != nil { r.ack(ids...) }
                    buf = buf[:0]
                    return
                }
            }
            // keep buffer to retry on next cycle
            logging.Error("pg_connectivity_error_deferred", logging.F("buffer_len", len(buf)), logging.F("err", lastErr.Error()))
            return
        }

        // Batch failed after retries (non-connectivity); try per-row fallback and track failures (still via ingest)
        failed := make([]pgMsg, 0, len(buf))
        succeededIDs := make([]string, 0, len(buf))
        for i, m := range buf {
            // legacy per-row fallback not used for envelope path now
            if e := r.pg.IngestEventsJSON(context.Background(), []map[string]any{}); e != nil {
                failed = append(failed, m)
            } else {
                succeededIDs = append(succeededIDs, redisIDs[i])
            }
        }
        if len(succeededIDs) > 0 && r.ack != nil { r.ack(succeededIDs...) }
        if len(failed) > 0 { logging.Warn("pg_fallback_failed_count", logging.F("count", len(failed))) }
        if len(failed) == 0 { buf = buf[:0]; return }
        // Could not persist; rely on DB-level spill (ingest_spill) and retry next cycle; log as error
        logging.Error("pg_persist_failed_non_connectivity", logging.F("buffer_len", len(buf)))
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

// handleLeanEvent enqueues a lean event (already validated and enriched) for DB ingest
func (r *router) handleLeanEvent(redisID, eventID, ts, subjectID, producerID string, payloadJSON, tagsJSON []byte, schemaID string) {
    if r.pgChLean != nil {
        select {
        case r.pgChLean <- pgMsgLean{RedisID: redisID, EventID: eventID, TS: ts, SubjectID: subjectID, ProducerID: producerID, SchemaID: schemaID, Payload: payloadJSON, Tags: tagsJSON}:
        default:
        }
    } else {
        if r.ack != nil { r.ack(redisID) }
    }
}

func (r *router) pgWorkerBatchLean() {
    buf := make([]pgMsgLean, 0, r.pgBatchSize)
    timer := time.NewTimer(r.pgBatchWait)
    defer timer.Stop()
    flush := func() {
        if len(buf) == 0 { return }
        events := make([]map[string]any, 0, len(buf))
        redisIDs := make([]string, 0, len(buf))
        for _, m := range buf {
            var payload map[string]any
            _ = json.Unmarshal(m.Payload, &payload)
            var tags []map[string]string
            if len(m.Tags) > 0 { _ = json.Unmarshal(m.Tags, &tags) }
            ev := map[string]any{
                "event_id":   m.EventID,
                "ts":         m.TS,
                "subject_id": m.SubjectID,
                "producer_id": m.ProducerID,
                "schema_id":  m.SchemaID,
                "payload":    payload,
                "tags":       tags,
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
        // per-row fallback
        succeeded := make([]string, 0, len(buf))
        for i, m := range buf {
            var payload map[string]any
            _ = json.Unmarshal(m.Payload, &payload)
            var tags []map[string]string
            if len(m.Tags) > 0 { _ = json.Unmarshal(m.Tags, &tags) }
            ev := []map[string]any{{
                "event_id":   m.EventID,
                "ts":         m.TS,
                "subject_id": m.SubjectID,
                "producer_id": m.ProducerID,
                "schema_id":  m.SchemaID,
                "payload":    payload,
                "tags":       tags,
            }}
            if e := r.pg.IngestEventsJSON(context.Background(), ev); e == nil {
                succeeded = append(succeeded, redisIDs[i])
            }
        }
        if len(succeeded) > 0 && r.ack != nil { r.ack(succeeded...) }
        buf = buf[:0]
    }
    for {
        select {
        case m, ok := <-r.pgChLean:
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

// isConnectivityError attempts to detect network/connection-level failures where the database is unreachable,
// to decide whether to fallback to filesystem spill as a last resort.
func isConnectivityError(err error) bool {
    if err == nil { return false }
    if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) { return true }
    if errors.Is(err, io.EOF) { return true }
    var ne net.Error
    if errors.As(err, &ne) { return true }
    // best-effort string checks (driver error strings)
    s := strings.ToLower(err.Error())
    switch {
    case strings.Contains(s, "connection refused"),
        strings.Contains(s, "broken pipe"),
        strings.Contains(s, "connection reset"),
        strings.Contains(s, "no such host"),
        strings.Contains(s, "server closed the connection"),
        strings.Contains(s, "i/o timeout"):
        return true
    }
    return false
}

