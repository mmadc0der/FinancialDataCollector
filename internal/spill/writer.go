package spill

import (
    "bufio"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/metrics"
)

type Writer struct {
    cfg kernelcfg.SpillConfig
    mu  sync.Mutex
    f   *os.File
    buf *bufio.Writer
    size int64
}

func NewWriter(cfg kernelcfg.SpillConfig) (*Writer, error) {
    if !cfg.Enabled { return &Writer{cfg: cfg}, nil }
    if err := os.MkdirAll(cfg.Directory, 0o755); err != nil { return nil, err }
    w := &Writer{cfg: cfg}
    if err := w.rotate(); err != nil { return nil, err }
    return w, nil
}

func (w *Writer) rotate() error {
    if !w.cfg.Enabled { return nil }
    if w.f != nil { _ = w.buf.Flush(); _ = w.f.Close() }
    name := fmt.Sprintf("spill_%s.ndjson", time.Now().Format("20060102_150405"))
    path := filepath.Join(w.cfg.Directory, name)
    f, err := os.Create(path)
    if err != nil { return err }
    w.f = f
    w.buf = bufio.NewWriterSize(f, 1<<20)
    w.size = 0
    return nil
}

func (w *Writer) WriteEnvelopes(envs []protocol.Envelope) error {
    if !w.cfg.Enabled || len(envs) == 0 { return nil }
    w.mu.Lock()
    defer w.mu.Unlock()
    for _, e := range envs {
        b, _ := json.Marshal(e)
        if w.cfg.RotateMB > 0 && w.size+int64(len(b)+1) > int64(w.cfg.RotateMB)*1024*1024 {
            if err := w.rotate(); err != nil { return err }
        }
        if _, err := w.buf.Write(b); err != nil { return err }
        if err := w.buf.WriteByte('\n'); err != nil { return err }
        w.size += int64(len(b)+1)
        metrics.SpillWriteTotal.Inc()
        metrics.SpillBytesTotal.Add(float64(len(b)+1))
    }
    _ = w.buf.Flush()
    return nil
}


