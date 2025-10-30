package spill

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/logging"
	"github.com/example/data-kernel/internal/metrics"
)

// Writer persists batches to the local filesystem as a last-resort buffer.
// Files are simple JSON arrays: [{...event...}, ...]
type Writer struct{
    dir string
}

func NewWriter(dir string) (*Writer, error) {
    if strings.TrimSpace(dir) == "" {
        dir = "./spill"
    }
    if err := os.MkdirAll(dir, 0o755); err != nil { return nil, err }
    return &Writer{dir: dir}, nil
}

func (w *Writer) Write(events []map[string]any) (string, int64, error) {
    ev := logging.NewEventLogger()
    
    if len(events) == 0 { return "", 0, nil }
    b, err := json.Marshal(events)
    if err != nil { return "", 0, err }
    name := time.Now().UTC().Format("20060102T150405.000000000") + ".json"
    path := filepath.Join(w.dir, name)
    if err := os.WriteFile(path, b, 0o640); err != nil { 
        ev.Infra("write", "spill", "failed", fmt.Sprintf("failed to write spill file %s: %v", name, err))
        return "", 0, err 
    }
    metrics.SpillWriteTotal.Inc()
    metrics.SpillBytesTotal.Add(float64(len(b)))
    updateFilesGauge(w.dir)
    ev.Infra("write", "spill", "success", fmt.Sprintf("spill write: file=%s, events=%d", name, len(events)))
    return path, int64(len(b)), nil
}

// Replayer re-ingests spilled batches into Postgres until the directory is empty.
type Replayer struct{
    dir string
    pg  *data.Postgres
    interval time.Duration
    stop chan struct{}
}

func NewReplayer(dir string, pg *data.Postgres) *Replayer {
    if strings.TrimSpace(dir) == "" { dir = "./spill" }
    return &Replayer{dir: dir, pg: pg, interval: 3 * time.Second, stop: make(chan struct{})}
}

func (r *Replayer) Start() {
    go func() {
        ticker := time.NewTicker(r.interval)
        defer ticker.Stop()
        for {
            select {
            case <-r.stop:
                return
            case <-ticker.C:
                r.replayOnce()
            }
        }
    }()
}

func (r *Replayer) Stop() { close(r.stop) }

func (r *Replayer) replayOnce() {
    ev := logging.NewEventLogger()
    
    if r.pg == nil { return }
    entries, err := os.ReadDir(r.dir)
    if err != nil { return }
    for _, e := range entries {
        if e.IsDir() { continue }
        if !strings.HasSuffix(e.Name(), ".json") { continue }
        p := filepath.Join(r.dir, e.Name())
        b, err := os.ReadFile(p)
        if err != nil { continue }
        var events []map[string]any
        if err := json.Unmarshal(b, &events); err != nil { _ = os.Remove(p); continue }
        if len(events) == 0 { _ = os.Remove(p); continue }
        if err := r.pg.IngestEventsJSON(nil, events); err != nil {
            // keep file; treat only connectivity as retryable; non-connectivity errors will be retried later
            if !isConnectivityError(err) {
                ev.Infra("write", "postgres", "failed", fmt.Sprintf("spill replay error: file=%s, error=%v", e.Name(), err))
            }
            continue
        }
        _ = os.Remove(p)
        metrics.SpillReplayTotal.Inc()
        updateFilesGauge(r.dir)
        ev.Infra("write", "postgres", "success", fmt.Sprintf("spill replay success: file=%s, events=%d", e.Name(), len(events)))
    }
}

func updateFilesGauge(dir string) {
    var n int64
    _ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
        if err != nil { return nil }
        if d.IsDir() { return nil }
        if strings.HasSuffix(d.Name(), ".json") { n++ }
        return nil
    })
    metrics.SpillFilesGauge.Set(float64(n))
}

// Minimal duplication of connectivity check to avoid import cycles.
func isConnectivityError(err error) bool {
    if err == nil { return false }
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


