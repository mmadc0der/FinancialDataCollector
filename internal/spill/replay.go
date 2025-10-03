package spill

import (
    "bufio"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "time"

    "context"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/metrics"
)

type Replayer struct {
    cfg kernelcfg.SpillConfig
}

func NewReplayer(cfg kernelcfg.SpillConfig) *Replayer { return &Replayer{cfg: cfg} }

// Start periodically scans the spill directory for ndjson files and replays them to Postgres.
func (r *Replayer) Start(ctx context.Context, pg *data.Postgres) {
    if !r.cfg.Enabled || pg == nil { return }
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            _ = r.replayOnce(ctx, pg)
        }
    }
}

func (r *Replayer) replayOnce(ctx context.Context, pg *data.Postgres) error {
    entries, err := os.ReadDir(r.cfg.Directory)
    if err != nil { return err }
    files := 0
    for _, e := range entries {
        if e.IsDir() { continue }
        name := e.Name()
        if !strings.HasPrefix(name, "spill_") || !strings.HasSuffix(name, ".ndjson") { continue }
        files++
        path := filepath.Join(r.cfg.Directory, name)
        f, err := os.Open(path)
        if err != nil { continue }
        scanner := bufio.NewScanner(f)
        buf := make([]byte, 1<<20)
        scanner.Buffer(buf, 8<<20)
        envs := make([]protocol.Envelope, 0, 1000)
        for scanner.Scan() {
            var env protocol.Envelope
            if err := json.Unmarshal(scanner.Bytes(), &env); err == nil {
                envs = append(envs, env)
            }
        }
        _ = f.Close()
        if len(envs) == 0 { _ = os.Remove(path); continue }
        rows := make([]data.EnvelopeRow, 0, len(envs))
        for _, e := range envs {
            rows = append(rows, data.EnvelopeRow{ID: e.ID, Type: e.Type, Version: e.Version, TS: time.Unix(0, e.TS), Data: e.Data})
        }
        if err := pg.InsertEnvelopesBatch(ctx, rows); err == nil {
            metrics.SpillReplayTotal.Add(float64(len(rows)))
            _ = os.Remove(path)
        }
    }
    metrics.SpillFilesGauge.Set(float64(files))
    return nil
}


