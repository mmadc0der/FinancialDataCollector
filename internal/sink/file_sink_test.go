package sink

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/data-kernel/internal/kernelcfg"
)

func TestNDJSONFileSink_WriteRotate(t *testing.T) {
	tmp, err := os.MkdirTemp("", "sink-*")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(tmp)
	cfg := kernelcfg.FileSinkConfig{Enabled: true, Directory: tmp, RotateMB: 1}
	s, err := NewNDJSONFileSink(cfg)
	if err != nil { t.Fatal(err) }
	defer s.Close()
	// write ~2.5 MiB to trigger rotation
	payload := make([]byte, 1024)
	for i := range payload { payload[i] = 'a' }
	for i := 0; i < 2600; i++ {
		if err := s.WriteJSON(map[string]any{"p": string(payload)}); err != nil { t.Fatal(err) }
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) < 2 { t.Fatalf("expected rotation to create multiple files, got %d in %s", len(entries), tmp) }
}

func TestNDJSONFileSink_CompressionGzip(t *testing.T) {
	tmp, err := os.MkdirTemp("", "sink-*")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(tmp)
	cfg := kernelcfg.FileSinkConfig{Enabled: true, Directory: tmp, Compression: "gzip"}
	s, err := NewNDJSONFileSink(cfg)
	if err != nil { t.Fatal(err) }
	defer s.Close()
	if err := s.WriteJSON(map[string]any{"x": 1}); err != nil { t.Fatal(err) }
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 { t.Fatalf("expected 1 file, got %d", len(entries)) }
	name := entries[0].Name()
	if filepath.Ext(name) != ".gz" && name[len(name)-3:] != ".gz" {
		t.Fatalf("expected gzip file, got %s", name)
	}
}

