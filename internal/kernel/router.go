package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
	"github.com/example/data-kernel/internal/logging"
	"github.com/example/data-kernel/internal/metrics"
	"github.com/example/data-kernel/internal/spill"
)

// Object pools for reducing GC pressure
var (
	// Pool for map[string]any used in JSON unmarshaling
	jsonMapPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]any)
		},
	}

	// Pool for []map[string]string used in tags
	tagsSlicePool = sync.Pool{
		New: func() interface{} {
			return make([]map[string]string, 0, 10)
		},
	}

	// Pool for []map[string]any used in events
	eventsSlicePool = sync.Pool{
		New: func() interface{} {
			return make([]map[string]any, 0, 100)
		},
	}
)

// MetricsBatcher batches metrics updates to reduce overhead
type MetricsBatcher struct {
	mu          sync.Mutex
	redisRead   int64
	redisAck    int64
	redisDLQ    int64
	authDenied  int64
	lastFlush   time.Time
	flushTicker *time.Ticker
}

func newMetricsBatcher() *MetricsBatcher {
	mb := &MetricsBatcher{
		flushTicker: time.NewTicker(10 * time.Second),
		lastFlush:   time.Now(),
	}
	go mb.flushLoop()
	return mb
}

func (mb *MetricsBatcher) flushLoop() {
	for range mb.flushTicker.C {
		mb.Flush()
	}
}

func (mb *MetricsBatcher) Flush() {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	if mb.redisRead > 0 {
		metrics.RedisReadTotal.Add(float64(mb.redisRead))
		mb.redisRead = 0
	}
	if mb.redisAck > 0 {
		metrics.RedisAckTotal.Add(float64(mb.redisAck))
		mb.redisAck = 0
	}
	if mb.redisDLQ > 0 {
		metrics.RedisDLQTotal.Add(float64(mb.redisDLQ))
		mb.redisDLQ = 0
	}
	if mb.authDenied > 0 {
		metrics.AuthDeniedTotal.Add(float64(mb.authDenied))
		mb.authDenied = 0
	}
	mb.lastFlush = time.Now()
}

func (mb *MetricsBatcher) IncRedisRead() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.redisRead++
}

func (mb *MetricsBatcher) IncRedisAck() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.redisAck++
}

func (mb *MetricsBatcher) IncRedisDLQ() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.redisDLQ++
}

func (mb *MetricsBatcher) IncAuthDenied() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.authDenied++
}

var globalMetricsBatcher = newMetricsBatcher()

// CircuitBreaker implements circuit breaker pattern for database operations
type CircuitBreaker struct {
    mu           sync.RWMutex
    failureCount int
    lastFailTime time.Time
    state        circuitState
    threshold    int
    timeout      time.Duration
}

type circuitState int

const (
    circuitClosed circuitState = iota
    circuitOpen
    circuitHalfOpen
)

func newCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
    return &CircuitBreaker{
        threshold: threshold,
        timeout:   timeout,
        state:     circuitClosed,
    }
}

func (cb *CircuitBreaker) canExecute() bool {
    cb.mu.RLock()
    defer cb.mu.RUnlock()

    switch cb.state {
    case circuitClosed:
        return true
    case circuitOpen:
        if time.Since(cb.lastFailTime) > cb.timeout {
            cb.mu.RUnlock()
            cb.mu.Lock()
            if cb.state == circuitOpen && time.Since(cb.lastFailTime) > cb.timeout {
                cb.state = circuitHalfOpen
            }
            cb.mu.Unlock()
            cb.mu.RLock()
            return cb.state == circuitHalfOpen
        }
        return false
    case circuitHalfOpen:
        return true
    default:
        return false
    }
}

func (cb *CircuitBreaker) onSuccess() {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    cb.failureCount = 0
    if cb.state == circuitHalfOpen {
        cb.state = circuitClosed
    }
}

func (cb *CircuitBreaker) onFailure() {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    cb.failureCount++
    cb.lastFailTime = time.Now()

    if cb.failureCount >= cb.threshold {
        cb.state = circuitOpen
    }
}

type router struct {
    pg   *data.Postgres
    rd   *data.Redis
    spw  *spill.Writer
    spr  *spill.Replayer
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
    // circuit breaker for database operations
    pgCircuitBreaker *CircuitBreaker
}

func newRouter(cfg *kernelcfg.Config, ack func(ids ...string)) (*router, error) {
    r := &router{
        publishEnabled: cfg.Redis.PublishEnabled,
        pgBatchSize: cfg.Postgres.BatchSize,
        pgBatchWait: time.Duration(cfg.Postgres.BatchMaxWaitMs) * time.Millisecond,
        ack: ack,
        pgCircuitBreaker: newCircuitBreaker(cfg.Postgres.CircuitBreakerThreshold, time.Duration(cfg.Postgres.CircuitBreakerTimeoutSeconds)*time.Second),
    }
    // pick defaults from config, may be empty which signals NULL in DB
    r.prodID = cfg.Postgres.DefaultProducerID
    r.schID = ""
    if pg, err := data.NewPostgres(cfg.Postgres); err == nil {
        r.pg = pg
        q := cfg.Postgres.QueueSize
        if q <= 0 { q = 1024 }
        r.pgCh = make(chan pgMsg, q)
        go r.pgWorkerBatch()
        r.pgChLean = make(chan pgMsgLean, q)
        go r.pgWorkerBatchLean()
        // start replayer
        r.spr = spill.NewReplayer("./spill", r.pg)
        r.spr.Start()
    } else {
        logging.Error("postgres_init_error", logging.Err(err))
        return nil, err
    }
    if rd, err := data.NewRedis(cfg.Redis); err == nil {
        r.rd = rd
        q := cfg.Redis.QueueSize
        if q <= 0 { q = 2048 }
        r.rdCh = make(chan rdMsg, q)
        go r.rdWorker()
    } else {
        logging.Error("redis_init_error", logging.Err(err))
        return nil, err
    }
    // spill disabled
    return r, nil
}

func (r *router) close() {
    if r.spr != nil { r.spr.Stop() }
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

        // Check circuit breaker before executing
        if !r.pgCircuitBreaker.canExecute() {
            logging.Warn("pg_circuit_breaker_open", logging.F("batch_size", len(events)))
            // Fall back to spill immediately when circuit is open
            if r.spw == nil {
                if w, e := spill.NewWriter("./spill"); e == nil { r.spw = w } else { logging.Error("spill_init_error", logging.Err(e)) }
            }
            if r.spw != nil {
                // Use async spill write to avoid blocking the main thread
                go func(events []map[string]any, redisIDs []string) {
                    if _, _, e := r.spw.Write(events); e == nil {
                        if r.ack != nil { r.ack(redisIDs...) }
                        logging.Warn("pg_circuit_spilled", logging.F("count", len(events)))
                    } else {
                        logging.Error("spill_write_failed", logging.F("count", len(events)), logging.Err(e))
                    }
                }(events, redisIDs)
                buf = buf[:0]
                return
            }
            logging.Error("pg_circuit_no_fallback", logging.F("buffer_len", len(buf)))
            return
        }

        err := r.pg.IngestEventsJSON(context.Background(), events)
        metrics.PGBatchDuration.Observe(time.Since(t0).Seconds())
        if err == nil {
            logging.Info("pg_batch_commit", logging.F("batch_size", len(events)), logging.F("duration_ms", time.Since(t0).Milliseconds()))
            r.pgCircuitBreaker.onSuccess()
            if r.ack != nil { r.ack(redisIDs...) }
            buf = buf[:0]
            return
        }

        r.pgCircuitBreaker.onFailure()
        logging.Warn("pg_batch_error", logging.F("err", err.Error()), logging.F("batch_size", len(events)))
        // Retry with configurable exponential backoff and jitter
        maxRetries := 3 // Use default since we don't have access to Redis config here
        baseBackoff := time.Duration(200) * time.Millisecond
        maxBackoff := time.Duration(5000) * time.Millisecond
        lastErr := err
        for i := 1; i <= maxRetries; i++ {
            // Calculate exponential backoff with jitter (±25% randomization)
            backoff := time.Duration(float64(baseBackoff) * float64(1<<uint(i-1)))
            if backoff > maxBackoff {
                backoff = maxBackoff
            }
            // Add jitter (±25%)
            jitter := time.Duration(float64(backoff) * 0.25 * (2.0*time.Now().UnixNano()%2 - 1.0))
            sleepTime := backoff + jitter
            if sleepTime < 0 {
                sleepTime = backoff / 2
            }

            time.Sleep(sleepTime)
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
        }
        // If this looks like a connectivity error, spill to filesystem (as last resort)
        if isConnectivityError(lastErr) {
            // write spill and ack Redis; router replayer will flush on reconnect
            if r.spw == nil {
                if w, e := spill.NewWriter("./spill"); e == nil { r.spw = w } else { logging.Error("spill_init_error", logging.Err(e)) }
            }
            if r.spw != nil {
                // Build events once for spill
                events := make([]map[string]any, 0, len(buf))
                redisIDs := make([]string, 0, len(buf))
                for _, m := range buf {
                    ev := map[string]any{}
                    events = append(events, ev)
                    redisIDs = append(redisIDs, m.RedisID)
                }
                if _, _, e := r.spw.Write(events); e == nil {
                    if r.ack != nil { r.ack(redisIDs...) }
                    logging.Warn("pg_connectivity_spilled", logging.F("count", len(events)))
                    buf = buf[:0]
                    return
                }
            }
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
        // Use pooled objects to reduce GC pressure
        events := eventsSlicePool.Get().([]map[string]any)[:0]
        redisIDs := make([]string, 0, len(buf))
        for _, m := range buf {
            // Reuse pooled map for payload
            payload := jsonMapPool.Get().(map[string]any)
            _ = json.Unmarshal(m.Payload, &payload)

            var tags []map[string]string
            if len(m.Tags) > 0 {
                tags = tagsSlicePool.Get().([]map[string]string)[:0]
                _ = json.Unmarshal(m.Tags, &tags)
            }

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
        // per-row fallback with object pooling
        succeeded := make([]string, 0, len(buf))
        for i, m := range buf {
            // Reuse pooled map for payload
            payload := jsonMapPool.Get().(map[string]any)
            _ = json.Unmarshal(m.Payload, &payload)

            var tags []map[string]string
            if len(m.Tags) > 0 {
                tags = tagsSlicePool.Get().([]map[string]string)[:0]
                _ = json.Unmarshal(m.Tags, &tags)
            }

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

