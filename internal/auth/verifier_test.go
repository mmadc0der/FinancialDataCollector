package auth

import (
    "context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
)

func b64raw(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func TestIssue_Success(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatalf("keygen: %v", err) }
	cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
	v, err := NewVerifier(cfg, nil, nil)
	if err != nil { t.Fatalf("new verifier: %v", err) }
    _, jti, _, err := v.Issue(nil, "producer-1", time.Minute, "test", "fp")
	if err != nil { t.Fatalf("issue: %v", err) }
    if jti == "" { t.Fatalf("empty jti") }
}

type fakeDB struct{
    exists bool
    pid string
    revoked bool
}
func (f *fakeDB) InsertProducerToken(ctx context.Context, producerID, jti string, exp time.Time, notes string) error { return nil }
func (f *fakeDB) TokenExists(ctx context.Context, jti string) (bool, string) { return f.exists, f.pid }
func (f *fakeDB) IsTokenRevoked(ctx context.Context, jti string) bool { return f.revoked }
func (f *fakeDB) RevokeToken(ctx context.Context, jti, reason string) error { f.revoked = true; return nil }

type fakeRedis struct{
    kv map[string]string
}
func (r *fakeRedis) Exists(ctx context.Context, keys ...string) (int64, error) { if _, ok := r.kv[keys[0]]; ok { return 1, nil }; return 0, nil }
func (r *fakeRedis) Get(ctx context.Context, key string) (string, error) { return r.kv[key], nil }
func (r *fakeRedis) Set(ctx context.Context, key string, value any, expiration time.Duration) error { if r.kv==nil { r.kv = map[string]string{} }; r.kv[key] = value.(string); return nil }
func (r *fakeRedis) Del(ctx context.Context, keys ...string) error { delete(r.kv, keys[0]); return nil }

func TestVerify_Success_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    // inject seams
    db := &fakeDB{exists: true, pid: "p1"}
    rd := &fakeRedis{kv: map[string]string{}}
    v.dbInsertToken = db.InsertProducerToken
    v.dbTokenExists = db.TokenExists
    v.dbIsTokenRevoked = db.IsTokenRevoked
    v.dbRevokeToken = db.RevokeToken
    v.redisExists = func(ctx context.Context, key string) (int64, error) { if _,ok:=rd.kv[key]; ok { return 1,nil }; return 0,nil }
    v.redisGet = func(ctx context.Context, key string) (string, error) { return rd.kv[key], nil }
    v.redisSet = func(ctx context.Context, key, value string, ttl time.Duration) error { rd.kv[key] = value; return nil }
    v.redisDel = func(ctx context.Context, key string) error { delete(rd.kv, key); return nil }

    tok, jti, _, err := v.Issue(nil, "p1", time.Minute, "", "fp")
    if err != nil { t.Fatalf("issue: %v", err) }
    pid, got, err := v.Verify(nil, tok)
    if err != nil { t.Fatalf("verify: %v", err) }
    if pid != "p1" || got != jti { t.Fatalf("mismatch pid/jti: %s/%s", pid, got) }
}

func TestVerify_BadSignature_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    v.dbTokenExists = db.TokenExists
    v.dbIsTokenRevoked = db.IsTokenRevoked
    tok, _, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    bt := []byte(tok)
    bt[len(bt)-1] ^= 0x01
    if _, _, err := v.Verify(nil, string(bt)); err == nil { t.Fatalf("expected bad_signature/b64 error") }
}

func TestVerify_Expired_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 0}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    v.dbTokenExists = db.TokenExists
    v.dbIsTokenRevoked = db.IsTokenRevoked
    tok, _, _, _ := v.Issue(nil, "p1", -1*time.Second, "", "")
    if _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected token_expired") }
}

func TestVerify_IssuerAudienceMismatch_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    v.dbTokenExists = db.TokenExists
    v.dbIsTokenRevoked = db.IsTokenRevoked
    tok, _, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    v.cfg.Issuer = "other"
    if _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected issuer/audience error") }
}

func TestVerify_RevokedViaRedis_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    v.dbTokenExists = db.TokenExists
    v.dbIsTokenRevoked = db.IsTokenRevoked
    tok, _, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    v.redisExists = func(ctx context.Context, key string) (int64, error) { if strings.Contains(key, "revoked:jti:") { return 1, nil }; return 0, nil }
    if _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected token_revoked via redis") }
}

func TestVerify_UnknownKid(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    tok, _, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    // New verifier with no public keys -> unknown kid
    cfg2 := kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "iss", Audience: "aud"}
    v2, _ := NewVerifier(cfg2, nil, nil)
    if _, _, err := v2.Verify(nil, tok); err == nil { t.Fatalf("expected unknown_kid") }
}


