package kernel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
)

// minimal fakes for pg and auth
type fakePG struct{}
func (f *fakePG) ApproveProducerKey(ctx any, fingerprint, name, schemaID, reviewer, notes string) (string, error) { return "pid-1", nil }
func (f *fakePG) Pool() any { return nil }

type fakeAU struct{}
func (f *fakeAU) Issue(ctx any, producerID string, ttl time.Duration, notes, fp string) (string, string, time.Time, error) { return "tok", "jti", time.Now().Add(time.Hour), nil }
func (f *fakeAU) Revoke(ctx any, jti, reason string) error { return nil }

func TestHandleApprove_UnauthorizedWithoutAdmin(t *testing.T) {
    k := &Kernel{cfg: &kernelcfg.Config{Auth: kernelcfg.AuthConfig{AdminSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAfake"}}}
    body := map[string]any{"fingerprint":"fp","name":"n","schema_id":"00000000-0000-0000-0000-000000000000","ttl_seconds":60}
    b, _ := json.Marshal(body)
    r := httptest.NewRequest(http.MethodPost, "/admin/approve", bytes.NewReader(b))
    w := httptest.NewRecorder()
    k.handleApprove(w, r)
    if w.Result().StatusCode != http.StatusUnauthorized {
        t.Fatalf("expected 401 without admin, got %d", w.Result().StatusCode)
    }
}

func TestHandleRevoke_BadRequest(t *testing.T) {
	k := &Kernel{cfg: &kernelcfg.Config{Auth: kernelcfg.AuthConfig{}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader([]byte("{}")))
	k.handleRevokeToken(w, r)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when not admin")
	}
}
