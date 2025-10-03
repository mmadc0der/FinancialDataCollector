package kernel

import (
    "context"
    "encoding/json"
    "time"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/sink"
    "github.com/example/data-kernel/internal/spill"
    "github.com/example/data-kernel/internal/logging"
)

type router struct {
    sinks *sink.NDJSONFileSink
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
}

func newRouter(cfg *kernelcfg.Config, ack func(ids ...string)) (*router, error) {
	fs, err := sink.NewNDJSONFileSink(cfg.Sinks.File)
	if err != nil {
		return nil, err
	}
    r := &router{sinks: fs, publishEnabled: cfg.Redis.PublishEnabled, pgBatchSize: cfg.Postgres.BatchSize, pgBatchWait: time.Duration(cfg.Postgres.BatchMaxWaitMs) * time.Millisecond, ack: ack}
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
    }
}

func (k *Kernel) routeRaw(msg []byte) {
    var env protocol.Envelope
    if err := json.Unmarshal(msg, &env); err != nil {
        return
    }
    if k.rt != nil {
        k.rt.handle(env)
    }
}

type pgMsg struct { RedisID string; Env protocol.Envelope }

func (r *router) pgWorkerBatch() {
    buf := make([]pgMsg, 0, r.pgBatchSize)
    timer := time.NewTimer(r.pgBatchWait)
    defer timer.Stop()
    flush := func() {
        if len(buf) == 0 { return }
        // Build rows for PG
        rows := make([]data.EnvelopeRow, 0, len(buf))
        redisIDs := make([]string, 0, len(buf))
        for _, m := range buf {
            var dataObj map[string]any
            _ = json.Unmarshal(m.Env.Data, &dataObj)
            var source, symbol string
            if s, ok := dataObj["source"].(string); ok { source = s }
            if s, ok := dataObj["symbol"].(string); ok { symbol = s }
            rows = append(rows, data.EnvelopeRow{ID: m.Env.ID, Type: m.Env.Type, Version: m.Env.Version, TS: time.Unix(0, m.Env.TS), Source: source, Symbol: symbol, Data: m.Env.Data})
            redisIDs = append(redisIDs, m.RedisID)
        }
        metrics.PGBatchSize.Observe(float64(len(rows)))
        t0 := time.Now()
        err := r.pg.InsertEnvelopesBatch(context.Background(), rows)
        metrics.PGBatchDuration.Observe(time.Since(t0).Seconds())
        if err == nil {
            logging.Info("pg_batch_commit", logging.F("batch_size", len(rows)), logging.F("duration_ms", time.Since(t0).Milliseconds()))
            if r.ack != nil { r.ack(redisIDs...) }
            buf = buf[:0]
            return
        }
        logging.Warn("pg_batch_error", logging.F("err", err.Error()), logging.F("batch_size", len(rows)))
        // Retry a few times with exponential backoff
        const maxRetries = 3
        backoff := 200 * time.Millisecond
        for i := 1; i <= maxRetries; i++ {
            time.Sleep(backoff)
            t1 := time.Now()
            if e := r.pg.InsertEnvelopesBatch(context.Background(), rows); e == nil {
                logging.Info("pg_batch_commit_retry", logging.F("attempt", i), logging.F("batch_size", len(rows)), logging.F("duration_ms", time.Since(t1).Milliseconds()))
                if r.ack != nil { r.ack(redisIDs...) }
                buf = buf[:0]
                return
            } else {
                logging.Warn("pg_batch_error_retry", logging.F("attempt", i), logging.F("err", e.Error()))
            }
            if backoff < 5*time.Second { backoff *= 2 }
        }
        // Batch failed after retries; try per-row fallback and track failures
        failed := make([]pgMsg, 0, len(buf))
        succeededIDs := make([]string, 0, len(buf))
        for i, row := range rows {
            if e := r.pg.InsertEnvelope(context.Background(), row.ID, row.Type, row.Version, row.TS, row.Source, row.Symbol, row.Data); e != nil {
                failed = append(failed, buf[i])
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

