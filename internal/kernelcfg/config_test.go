package kernelcfg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	tmp, err := os.MkdirTemp("", "cfg-*")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(tmp)
	cfgPath := filepath.Join(tmp, "kernel.yaml")
	// empty file -> defaults apply
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o644); err != nil { t.Fatal(err) }
	cfg, err := Load(cfgPath)
	if err != nil { t.Fatal(err) }
	if cfg.Server.Listen == "" || cfg.Sinks.File.Directory == "" || cfg.Modules.Dir == "" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	tmp, err := os.MkdirTemp("", "cfg-*")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(tmp)
	cfgPath := filepath.Join(tmp, "kernel.yaml")
	if err := os.WriteFile(cfgPath, []byte("server: {}\n"), 0o644); err != nil { t.Fatal(err) }
	// token via env var
	os.Setenv("KERNEL_AUTH_TOKEN", "sekret")
	defer os.Unsetenv("KERNEL_AUTH_TOKEN")
	cfg, err := Load(cfgPath)
	if err != nil { t.Fatal(err) }
	if cfg.Server.AuthToken != "sekret" { t.Fatalf("env override failed: %+v", cfg.Server) }
	// token via file var
	path := filepath.Join(tmp, "tok")
	_ = os.WriteFile(path, []byte("filetok\n"), 0o600)
	os.Setenv("KERNEL_AUTH_TOKEN_FILE", path)
	defer os.Unsetenv("KERNEL_AUTH_TOKEN_FILE")
	cfg, err = Load(cfgPath)
	if err != nil { t.Fatal(err) }
	if cfg.Server.AuthToken != "filetok" { t.Fatalf("file override failed: %+v", cfg.Server) }
}

