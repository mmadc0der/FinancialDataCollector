package spill

import (
    "bufio"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
)

func TestWriter_WriteAndRotate(t *testing.T) {
    dir := t.TempDir()
    w, err := NewWriter(kernelcfg.SpillConfig{Enabled: true, Directory: dir, RotateMB: 1})
    if err != nil { t.Fatalf("new writer: %v", err) }
    defer w.Close()
    envs := []protocol.Envelope{
        {Version: "0.1.0", Type: "data", ID: "A", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"k":1}`)},
        {Version: "0.1.0", Type: "data", ID: "B", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"k":2}`)},
    }
    if err := w.WriteEnvelopes(envs); err != nil { t.Fatalf("write: %v", err) }
    // Find a file and assert two lines present
    entries, _ := os.ReadDir(dir)
    if len(entries) == 0 { t.Fatalf("expected spill file created") }
    f, err := os.Open(filepath.Join(dir, entries[0].Name()))
    if err != nil { t.Fatalf("open: %v", err) }
    defer f.Close()
    s := bufio.NewScanner(f)
    lines := 0
    for s.Scan() { lines++ }
    if lines == 0 { t.Fatalf("expected lines written, got 0") }
}
