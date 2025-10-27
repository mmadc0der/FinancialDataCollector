package metrics

import (
    "net/http"

    prom "github.com/prometheus/client_golang/prometheus"
    promhttp "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    IngestDropped = prom.NewCounter(prom.CounterOpts{Name: "kernel_ingest_dropped_total", Help: "Dropped messages due to backpressure"})
    RedisReadTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_redis_read_total", Help: "Messages read from Redis"})
    RedisAckTotal  = prom.NewCounter(prom.CounterOpts{Name: "kernel_redis_ack_total", Help: "Messages acked to Redis"})
    RedisDLQTotal  = prom.NewCounter(prom.CounterOpts{Name: "kernel_redis_dlq_total", Help: "Messages sent to DLQ"})
    RedisBatchDuration = prom.NewHistogram(prom.HistogramOpts{Name: "kernel_redis_batch_seconds", Help: "Duration of Redis read batches", Buckets: prom.DefBuckets})
    PGBatchSize = prom.NewHistogram(prom.HistogramOpts{Name: "kernel_pg_batch_size", Help: "Rows per batch to Postgres", Buckets: []float64{1,10,50,100,200,500,1000,2000,5000}})
    PGBatchDuration = prom.NewHistogram(prom.HistogramOpts{Name: "kernel_pg_batch_seconds", Help: "Duration of Postgres batch insert", Buckets: prom.DefBuckets})
    PGPersistTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_pg_commit_total", Help: "Batches successfully committed to Postgres"})
    PGErrorsTotal  = prom.NewCounter(prom.CounterOpts{Name: "kernel_pg_errors_total", Help: "Errors when writing to Postgres"})
    SpillWriteTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_spill_write_total", Help: "Batches written to spill"})
    SpillBytesTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_spill_bytes_total", Help: "Bytes written to spill"})
    SpillReplayTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_spill_replay_total", Help: "Batches replayed from spill"})
    RedisPendingGauge = prom.NewGauge(prom.GaugeOpts{Name: "kernel_redis_pending", Help: "Approx pending messages in consumer group"})
    RedisStreamLenGauge = prom.NewGauge(prom.GaugeOpts{Name: "kernel_redis_stream_length", Help: "Approx length of Redis stream"})
    SpillFilesGauge = prom.NewGauge(prom.GaugeOpts{Name: "kernel_spill_files", Help: "Number of spill files on disk"})
    AuthDeniedTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_auth_denied_total", Help: "Messages rejected due to failed authentication"})
    // Registration rate limiting metrics
    RegistrationRateLimited = prom.NewCounter(prom.CounterOpts{Name: "kernel_registration_rate_limited_total", Help: "Registration requests rate limited"})
    RegistrationRateLimitErrors = prom.NewCounter(prom.CounterOpts{Name: "kernel_registration_rate_limit_errors_total", Help: "Errors in rate limiting checks"})
    // Security metrics
    AdminMTLSDenied = prom.NewCounter(prom.CounterOpts{Name: "kernel_admin_mtls_denied_total", Help: "Admin requests denied due to missing/invalid mTLS"})
    AdminSigInvalid = prom.NewCounter(prom.CounterOpts{Name: "kernel_admin_signature_invalid_total", Help: "Admin requests with invalid detached signature"})
    AdminReplay = prom.NewCounter(prom.CounterOpts{Name: "kernel_admin_replay_total", Help: "Admin requests rejected due to nonce replay"})
    CanonicalVerifyFail = prom.NewCounter(prom.CounterOpts{Name: "kernel_canonical_verify_fail_total", Help: "Producer signature verification failures after canonicalization"})
    RateLimitAllow = prom.NewCounterVec(prom.CounterOpts{Name: "kernel_rate_limit_allow_total", Help: "Allowed ops by distributed rate limiter"}, []string{"op"})
    RateLimitDeny = prom.NewCounterVec(prom.CounterOpts{Name: "kernel_rate_limit_deny_total", Help: "Denied ops by distributed rate limiter"}, []string{"op"})
)

func init() {
    prom.MustRegister(
        IngestDropped,
        RedisReadTotal, RedisAckTotal, RedisDLQTotal, RedisBatchDuration,
        PGBatchSize, PGBatchDuration, PGPersistTotal, PGErrorsTotal,
        SpillWriteTotal, SpillBytesTotal, SpillReplayTotal,
        RedisPendingGauge, RedisStreamLenGauge, SpillFilesGauge,
        AuthDeniedTotal,
        RegistrationRateLimited, RegistrationRateLimitErrors,
        AdminMTLSDenied, AdminSigInvalid, AdminReplay, CanonicalVerifyFail,
        RateLimitAllow, RateLimitDeny,
    )
}

func Handler() http.Handler { return promhttp.Handler() }


