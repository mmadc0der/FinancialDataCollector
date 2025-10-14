package spill

import (
    "context"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
)

func TestReplayOnce_IngestsAndRemoves(t *testing.T) {
    dir := t.TempDir()
    // create a spill file with two envelopes
    envs := []protocol.Envelope{
        {Version: "0.1.0", Type: "data", ID: "A", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"k":1}`)},
        {Version: "0.1.0", Type: "data", ID: "B", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"k":2}`)},
    }
    path := filepath.Join(dir, "spill_test.ndjson")
    f, err := os.Create(path)
    if err != nil { t.Fatalf("create: %v", err) }
    for _, e := range envs {
        b, _ := json.Marshal(e)
        _, _ = f.Write(append(b, '\n'))
    }
    _ = f.Close()

    r := &Replayer{cfg: kernelcfg.SpillConfig{Enabled: true, Directory: dir}}
    // Use Postgres with nil pool so IngestEventsJSON returns nil (success)
    pg := &data.Postgres{}
    if err := r.replayOnce(context.Background(), pg); err != nil { t.Fatalf("replayOnce: %v", err) }
    if _, err := os.Stat(path); !os.IsNotExist(err) {
        t.Fatalf("expected spill file to be removed after successful ingest")
    }
}


