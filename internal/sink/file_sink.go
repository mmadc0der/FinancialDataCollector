package sink

import (
    "bufio"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    ulid "github.com/oklog/ulid/v2"
)

type NDJSONFileSink struct {
	cfg   kernelcfg.FileSinkConfig
	mu    sync.Mutex
	file  *os.File
	buf   *bufio.Writer
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
		s.file.Close()
	}
	name := fmt.Sprintf("%s_%s.ndjson", time.Now().Format("20060102"), ulid.Make().String())
	path := filepath.Join(s.cfg.Directory, name)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	s.file = f
	s.buf = bufio.NewWriterSize(f, 1<<20)
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
	return nil
}

func (s *NDJSONFileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf != nil {
		s.buf.Flush()
	}
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

