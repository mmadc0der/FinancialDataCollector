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
        // Re-ingest via the same database ingest function
        events := make([]map[string]any, 0, len(envs))
        for _, e := range envs {
            var payload map[string]any
            _ = json.Unmarshal(e.Data, &payload)
            tags := make([]map[string]string, 0, 2)
            if s, ok := payload["source"].(string); ok && s != "" { tags = append(tags, map[string]string{"key":"core.source","value":s}) }
            if s, ok := payload["symbol"].(string); ok && s != "" { tags = append(tags, map[string]string{"key":"core.symbol","value":s}) }
            events = append(events, map[string]any{
                "event_id": e.ID,
                "ts": time.Unix(0, e.TS).UTC().Format(time.RFC3339Nano),
                "subject_id": nil,
                "producer_id": nil,
                "schema_id": nil,
                "payload": payload,
                "tags": tags,
            })
        }
        if err := pg.IngestEventsJSON(ctx, events); err == nil {
            metrics.SpillReplayTotal.Add(float64(len(events)))
            _ = os.Remove(path)
        }
    }
    metrics.SpillFilesGauge.Set(float64(files))
    return nil
}


