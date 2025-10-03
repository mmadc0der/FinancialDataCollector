package sink

import (
    "bufio"
    "encoding/json"
    "fmt"
    "compress/gzip"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/metrics"
    ulid "github.com/oklog/ulid/v2"
)

type NDJSONFileSink struct {
	cfg   kernelcfg.FileSinkConfig
	mu    sync.Mutex
	file  *os.File
	buf   *bufio.Writer
    gz    *gzip.Writer
	size  int64
	day   int
}

func NewNDJSONFileSink(cfg kernelcfg.FileSinkConfig) (*NDJSONFileSink, error) {
	if !cfg.Enabled {
		return &NDJSONFileSink{cfg: cfg}, nil
	}
	if err := os.MkdirAll(cfg.Directory, 0o755); err != nil {
		return nil, err
	}
	s := &NDJSONFileSink{cfg: cfg}
	if err := s.rotate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *NDJSONFileSink) rotate() error {
	if !s.cfg.Enabled {
		return nil
	}
	if s.file != nil {
        s.buf.Flush()
        if s.gz != nil { s.gz.Flush(); s.gz.Close(); s.gz = nil }
		s.file.Close()
	}
    ext := "ndjson"
    if s.cfg.Compression == "gzip" { ext = "ndjson.gz" }
    name := fmt.Sprintf("%s_%s.%s", time.Now().Format("20060102"), ulid.Make().String(), ext)
	path := filepath.Join(s.cfg.Directory, name)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	s.file = f
    if s.cfg.Compression == "gzip" {
        s.gz = gzip.NewWriter(f)
        s.buf = bufio.NewWriterSize(s.gz, 1<<20)
    } else {
        s.buf = bufio.NewWriterSize(f, 1<<20)
    }
	s.size = 0
	s.day = time.Now().Day()
	return nil
}

func (s *NDJSONFileSink) WriteJSON(obj any) error {
	if !s.cfg.Enabled {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	if s.cfg.RotateDaily && time.Now().Day() != s.day { // day rollover
		if err := s.rotate(); err != nil {
			return err
		}
	}
	if s.cfg.RotateMB > 0 && s.size+int64(len(b)) > int64(s.cfg.RotateMB)*1024*1024 {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	if _, err := s.buf.Write(b); err != nil {
		return err
	}
	if err := s.buf.WriteByte('\n'); err != nil {
		return err
	}
    s.size += int64(len(b) + 1)
    metrics.FileSinkBytes.Add(float64(len(b) + 1))
    // metrics
    // avoid importing metrics here to keep sink generic; optionally hook via router
    // periodic flush to bound data loss
    if s.size% (1<<20) == 0 { // every ~1MiB
        _ = s.buf.Flush()
    }
	return nil
}

func (s *NDJSONFileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf != nil {
		s.buf.Flush()
	}
    if s.gz != nil { s.gz.Flush(); s.gz.Close() }
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

