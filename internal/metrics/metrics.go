package metrics

import (
    "net/http"

    prom "github.com/prometheus/client_golang/prometheus"
    promhttp "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    WSConnections = prom.NewGauge(prom.GaugeOpts{Name: "kernel_ws_connections", Help: "Active WS connections"})
    IngestDropped = prom.NewCounter(prom.CounterOpts{Name: "kernel_ingest_dropped_total", Help: "Dropped messages due to backpressure"})
    FileSinkBytes = prom.NewCounter(prom.CounterOpts{Name: "kernel_filesink_bytes_total", Help: "Bytes written to file sink"})
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
)

func init() {
    prom.MustRegister(WSConnections, IngestDropped, FileSinkBytes, RedisReadTotal, RedisAckTotal, RedisDLQTotal, RedisBatchDuration, PGBatchSize, PGBatchDuration, PGPersistTotal, PGErrorsTotal, SpillWriteTotal, SpillBytesTotal, SpillReplayTotal)
}

func Handler() http.Handler { return promhttp.Handler() }


