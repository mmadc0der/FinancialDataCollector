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
)

func init() {
    prom.MustRegister(WSConnections, IngestDropped, FileSinkBytes)
}

func Handler() http.Handler { return promhttp.Handler() }


