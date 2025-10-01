package modulespec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidAndInvalid(t *testing.T) {
	tmp, err := os.MkdirTemp("", "mods-*")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(tmp)
	good := filepath.Join(tmp, "ok.yaml")
	bad := filepath.Join(tmp, "bad.yaml")
	if err := os.WriteFile(good, []byte("name: x\ncommand: /bin/echo\nargs: [hello]\n"), 0o644); err != nil { t.Fatal(err) }
	if err := os.WriteFile(bad, []byte("name: y\n"), 0o644); err != nil { t.Fatal(err) }
	if _, err := Load(good); err != nil { t.Fatalf("unexpected: %v", err) }
	if _, err := Load(bad); err == nil { t.Fatalf("expected error for empty command") }
}

