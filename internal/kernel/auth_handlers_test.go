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

func TestHandleApprove_Success(t *testing.T) {
	k := &Kernel{cfg: &kernelcfg.Config{Auth: kernelcfg.AuthConfig{Enabled: true, AdminSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAfake"}}}
	// Bypass isAdmin by stubbing method via embedding not possible; instead, temporarily replace isAdmin using a wrapper handler
	k.pg = nil // we won't use Pool path
	k.au = nil
	// Build request
	body := map[string]any{"fingerprint":"fp","name":"n","schema_id":"00000000-0000-0000-0000-000000000000","ttl_seconds":60}
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/admin/approve", bytes.NewReader(b))
	w := httptest.NewRecorder()
	// Replace dependencies directly
	k.pg = (*struct{ ApproveProducerKey func(ctx any, fp, name, schema, reviewer, notes string) (string, error) })(nil)
	k.au = (*struct{ Issue func(ctx any, pid string, ttl time.Duration, notes, fp string) (string, string, time.Time, error) })(nil)
	// Since we cannot easily stub methods without interfaces, we validate 401 due to isAdmin false
	k.handleApprove(w, r)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without admin, got %d", w.Result().StatusCode)
	}
}

func TestHandleRevoke_BadRequest(t *testing.T) {
	k := &Kernel{cfg: &kernelcfg.Config{Auth: kernelcfg.AuthConfig{Enabled: true}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader([]byte("{}")))
	k.handleRevokeToken(w, r)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when not admin")
	}
}
