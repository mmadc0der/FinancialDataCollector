package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/example/data-kernel/internal/kernel"
	"github.com/example/data-kernel/internal/kernelcfg"
)

type KernelInstance struct {
	URL      string
	Config   string
	TempDir  string
	cancel   context.CancelFunc
}

func (k *KernelInstance) Close() {
	if k.cancel != nil {
		k.cancel()
	}
	if k.TempDir != "" {
		_ = os.RemoveAll(k.TempDir)
	}
}

// StartKernel starts the kernel with a temporary configuration suitable for tests.
// It returns an instance with ws URL and a Close method to stop and cleanup.
func StartKernel(t *testing.T, override func(*kernelcfg.Config)) *KernelInstance {
	t.Helper()
	// pick a free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	tmp, err := os.MkdirTemp("", "kernel-test-*")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}

	// random token to avoid accidental collisions
	var tokBytes [16]byte
	_, _ = rand.Read(tokBytes[:])
	token := hex.EncodeToString(tokBytes[:])

	cfg := &kernelcfg.Config{}
	// defaults via Load would also apply; we build explicitly to be clear
	cfg.Server.Listen = addr
	cfg.Server.AuthToken = token
	cfg.Server.MaxMessageBytes = 1 << 20
	cfg.Server.ReadTimeoutMs = 3000
	cfg.Server.WindowSize = 8
	cfg.Sinks.File.Enabled = true
	cfg.Sinks.File.Directory = filepath.Join(tmp, "out")
	cfg.Sinks.File.RotateMB = 8
	cfg.Sinks.File.RotateDaily = false
	cfg.Sinks.File.Compression = ""
	cfg.Sinks.File.FlushEveryWrites = 1
	cfg.Modules.Dir = filepath.Join(tmp, "modules.d")
	cfg.Postgres.Enabled = false
	cfg.Redis.Enabled = false

	if override != nil {
		override(cfg)
	}

	if err := os.MkdirAll(cfg.Sinks.File.Directory, 0o755); err != nil {
		t.Fatalf("mkdir sink: %v", err)
	}
	if err := os.MkdirAll(cfg.Modules.Dir, 0o755); err != nil {
		t.Fatalf("mkdir modules: %v", err)
	}

	// write YAML config to file
	confPath := filepath.Join(tmp, "kernel.yaml")
	b, err := yaml.Marshal(cfg)
	if err != nil { t.Fatalf("yaml: %v", err) }
	if err := os.WriteFile(confPath, b, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// start kernel
	ctx, cancel := context.WithCancel(context.Background())
	krn, err := kernel.NewKernel(confPath)
	if err != nil { t.Fatalf("new kernel: %v", err) }
	go func() { _ = krn.Start(ctx) }()

	// wait briefly for server to be ready
	time.Sleep(200 * time.Millisecond)

	return &KernelInstance{
		URL:     "ws://" + addr + "/ws",
		Config:  confPath,
		TempDir: tmp,
		cancel:  cancel,
	}
}

