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
    SpillWriteTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_spill_write_total", Help: "Envelopes written to spill"})
    SpillBytesTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_spill_bytes_total", Help: "Bytes written to spill"})
    SpillReplayTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_spill_replay_total", Help: "Envelopes replayed from spill"})
    RedisPendingGauge = prom.NewGauge(prom.GaugeOpts{Name: "kernel_redis_pending", Help: "Approx pending messages in consumer group"})
    RedisStreamLenGauge = prom.NewGauge(prom.GaugeOpts{Name: "kernel_redis_stream_len", Help: "Approx length of the ingest stream"})
    SpillFilesGauge = prom.NewGauge(prom.GaugeOpts{Name: "kernel_spill_files", Help: "Number of spill files on disk"})
    AuthDeniedTotal = prom.NewCounter(prom.CounterOpts{Name: "kernel_auth_denied_total", Help: "Messages rejected due to failed authentication"})
)

func init() {
    prom.MustRegister(IngestDropped, RedisReadTotal, RedisAckTotal, RedisDLQTotal, RedisBatchDuration, PGBatchSize, PGBatchDuration, PGPersistTotal, PGErrorsTotal, SpillWriteTotal, SpillBytesTotal, SpillReplayTotal, RedisPendingGauge, RedisStreamLenGauge, SpillFilesGauge, AuthDeniedTotal)
}

func Handler() http.Handler { return promhttp.Handler() }


