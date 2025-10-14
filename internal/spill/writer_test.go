package spill

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
)

func TestWriterRotateAndWrite(t *testing.T) {
    dir := t.TempDir()
    w, err := NewWriter(kernelcfg.SpillConfig{Enabled: true, Directory: dir, RotateMB: 1})
    if err != nil { t.Fatalf("new writer: %v", err) }
    defer w.Close()
    // write a couple of envelopes
    envs := []protocol.Envelope{{Version: protocol.Version, Type: "data", ID: "A", TS: 1}, {Version: protocol.Version, Type: "data", ID: "B", TS: 2}}
    if err := w.WriteEnvelopes(envs); err != nil { t.Fatalf("write: %v", err) }
    // verify files exist
    entries, err := os.ReadDir(dir)
    if err != nil { t.Fatalf("readdir: %v", err) }
    if len(entries) == 0 { t.Fatalf("expected a spill file") }
    // file should be non-empty
    fi, err := os.Stat(filepath.Join(dir, entries[0].Name()))
    if err != nil { t.Fatalf("stat: %v", err) }
    if fi.Size() <= 0 { t.Fatalf("expected non-empty file") }
}
