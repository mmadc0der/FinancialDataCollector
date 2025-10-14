package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
)

func b64raw(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func TestIssueAndVerify_Success(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatalf("keygen: %v", err) }
	cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
	v, err := NewVerifier(cfg, nil, nil)
	if err != nil { t.Fatalf("new verifier: %v", err) }
	tok, jti, _, err := v.Issue(nil, "producer-1", time.Minute, "test", "fp")
	if err != nil { t.Fatalf("issue: %v", err) }
	if tok == "" || jti == "" { t.Fatalf("empty token or jti") }
	pid, gotJti, err := v.Verify(nil, tok)
	if err != nil { t.Fatalf("verify: %v", err) }
	if pid != "producer-1" || gotJti != jti { t.Fatalf("verify mismatch: pid=%s jti=%s", pid, gotJti) }
}

func TestVerify_UnknownKid(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
	v, err := NewVerifier(cfg, nil, nil)
	if err != nil { t.Fatalf("new verifier: %v", err) }
	tok, _, _, err := v.Issue(nil, "p", time.Minute, "", "")
	if err != nil { t.Fatalf("issue: %v", err) }
	if _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected error for unknown kid") }
}

func TestVerify_BadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
	v, _ := NewVerifier(cfg, nil, nil)
	tok, _, _, _ := v.Issue(nil, "p", time.Minute, "", "")
	// Corrupt the token by altering last char
	bt := []byte(tok)
	bt[len(bt)-1] ^= 0x01
	if _, _, err := v.Verify(nil, string(bt)); err == nil { t.Fatalf("expected bad signature or b64 error") }
}

func TestVerify_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 0}
	v, _ := NewVerifier(cfg, nil, nil)
	tok, _, _, _ := v.Issue(nil, "p", -1*time.Second, "", "")
	if _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected token_expired") }
}

func TestVerify_IssuerAudienceMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
	v, _ := NewVerifier(cfg, nil, nil)
	tok, _, _, _ := v.Issue(nil, "p", time.Minute, "", "")
	// Change verifier expected issuer
	v.cfg.Issuer = "other"
	if _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected issuer/audience error") }
}


