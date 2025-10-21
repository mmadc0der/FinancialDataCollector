package auth

import (
    "context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
    "strings"
	"testing"
	"time"

    data "github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
    "encoding/json"
    "golang.org/x/crypto/ssh"
)

func b64raw(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func TestIssue_Success(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatalf("keygen: %v", err) }
	cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
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
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    // inject seams via package-level vars
    db := &fakeDB{exists: true, pid: "p1"}
    rd := &fakeRedis{kv: map[string]string{}}
    authDbInsertToken = func(_ *data.Postgres, ctx context.Context, producerID, jti string, exp time.Time, notes string) error { return db.InsertProducerToken(ctx, producerID, jti, exp, notes) }
    authDbTokenExists = func(_ *data.Postgres, ctx context.Context, jti string) (bool, string) { return db.TokenExists(ctx, jti) }
    authDbIsTokenRevoked = func(_ *data.Postgres, ctx context.Context, jti string) bool { return db.IsTokenRevoked(ctx, jti) }
    authDbRevokeToken = func(_ *data.Postgres, ctx context.Context, jti, reason string) error { return db.RevokeToken(ctx, jti, reason) }
    authRedisExists = func(_ *data.Redis, ctx context.Context, key string) (int64, error) { if _,ok:=rd.kv[key]; ok { return 1,nil }; return 0,nil }
    authRedisGet = func(_ *data.Redis, ctx context.Context, key string) (string, error) { return rd.kv[key], nil }
    authRedisSet = func(_ *data.Redis, ctx context.Context, key, value string, ttl time.Duration) error { rd.kv[key] = value; return nil }
    authRedisDel = func(_ *data.Redis, ctx context.Context, key string) error { delete(rd.kv, key); return nil }

    tok, jti, _, err := v.Issue(nil, "p1", time.Minute, "", "fp")
    if err != nil { t.Fatalf("issue: %v", err) }
    pid, _, got, err := v.Verify(nil, tok)
    if err != nil { t.Fatalf("verify: %v", err) }
    if pid != "p1" || got != jti { t.Fatalf("mismatch pid/jti: %s/%s", pid, got) }
}

func TestVerify_BadSignature_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    authDbTokenExists = func(_ *data.Postgres, ctx context.Context, jti string) (bool, string) { return db.TokenExists(ctx, jti) }
    authDbIsTokenRevoked = func(_ *data.Postgres, ctx context.Context, jti string) bool { return db.IsTokenRevoked(ctx, jti) }
    tok, _, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    bt := []byte(tok)
    bt[len(bt)-1] ^= 0x01
    if _, _, _, err := v.Verify(nil, string(bt)); err == nil { t.Fatalf("expected bad_signature/b64 error") }
}

func TestVerify_Expired_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 0}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    authDbTokenExists = func(_ *data.Postgres, ctx context.Context, jti string) (bool, string) { return db.TokenExists(ctx, jti) }
    authDbIsTokenRevoked = func(_ *data.Postgres, ctx context.Context, jti string) bool { return db.IsTokenRevoked(ctx, jti) }
    tok, _, _, _ := v.Issue(nil, "p1", -1*time.Second, "", "")
    if _, _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected token_expired") }
}

func TestVerify_IssuerAudienceMismatch_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    authDbTokenExists = func(_ *data.Postgres, ctx context.Context, jti string) (bool, string) { return db.TokenExists(ctx, jti) }
    authDbIsTokenRevoked = func(_ *data.Postgres, ctx context.Context, jti string) bool { return db.IsTokenRevoked(ctx, jti) }
    tok, _, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    v.cfg.Issuer = "other"
    if _, _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected issuer/audience error") }
}

func TestVerify_RevokedViaRedis_WithFakes(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    authDbTokenExists = func(_ *data.Postgres, ctx context.Context, jti string) (bool, string) { return db.TokenExists(ctx, jti) }
    authDbIsTokenRevoked = func(_ *data.Postgres, ctx context.Context, jti string) bool { return db.IsTokenRevoked(ctx, jti) }
    tok, _, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    authRedisExists = func(_ *data.Redis, ctx context.Context, key string) (int64, error) { if strings.Contains(key, "revoked:jti:") { return 1, nil }; return 0, nil }
    if _, _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("expected token_revoked via redis") }
}

func TestVerify_UnknownKid(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    tok, _, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    // New verifier with no public keys -> unknown kid
    cfg2 := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud"}
    v2, _ := NewVerifier(cfg2, nil, nil)
    if _, _, _, err := v2.Verify(nil, tok); err == nil { t.Fatalf("expected unknown_kid") }
}

func TestIssue_TokenWithFingerprint(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    
    // Issue token with fingerprint
    tok, jti, _, err := v.Issue(nil, "p1", time.Minute, "test note", "fp-abc-123")
    if err != nil { t.Fatalf("issue: %v", err) }
    if jti == "" { t.Fatalf("empty jti") }
    
    // Verify token contains fingerprint in claims
    parts := strings.Split(tok, ".")
    if len(parts) != 3 { t.Fatalf("invalid token format") }
    cb, _ := base64.RawStdEncoding.DecodeString(parts[1])
    var c struct{ Fp string }
    if err := json.Unmarshal(cb, &c); err != nil { t.Fatalf("unmarshal claims: %v", err) }
    if c.Fp != "fp-abc-123" { t.Fatalf("fingerprint mismatch: got %s", c.Fp) }
}

func TestVerify_NBFClaimEdgeCases(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    // 5 second skew
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 5}
    v, _ := NewVerifier(cfg, nil, nil)
    db := &fakeDB{exists: true, pid: "p1"}
    rd := &fakeRedis{kv: map[string]string{}}
    authDbTokenExists = func(_ *data.Postgres, ctx context.Context, jti string) (bool, string) { return db.TokenExists(ctx, jti) }
    authDbIsTokenRevoked = func(_ *data.Postgres, ctx context.Context, jti string) bool { return db.IsTokenRevoked(ctx, jti) }
    authRedisExists = func(_ *data.Redis, ctx context.Context, key string) (int64, error) { if _,ok:=rd.kv[key]; ok { return 1,nil }; return 0,nil }
    authRedisGet = func(_ *data.Redis, ctx context.Context, key string) (string, error) { return rd.kv[key], nil }
    authRedisSet = func(_ *data.Redis, ctx context.Context, key, value string, ttl time.Duration) error { rd.kv[key] = value; return nil }
    
    // Issue token with short TTL (nbf = now - skew)
    tok, _, _, _ := v.Issue(nil, "p1", 1*time.Second, "", "")
    
    // Should verify immediately (nbf is in the past by skew amount)
    if _, _, _, err := v.Verify(nil, tok); err != nil { t.Fatalf("should verify: %v", err) }
    
    // Wait until token expires past skew
    time.Sleep(2 * time.Second)
    if _, _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("should be expired") }
}

func TestVerify_CacheHitForRevocation(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    
    db := &fakeDB{exists: true, pid: "p1", revoked: false}
    rd := &fakeRedis{kv: map[string]string{}}
    dbLookups := 0
    authDbTokenExists = func(_ *data.Postgres, ctx context.Context, jti string) (bool, string) { dbLookups++; return db.TokenExists(ctx, jti) }
    authDbIsTokenRevoked = func(_ *data.Postgres, ctx context.Context, jti string) bool { return db.IsTokenRevoked(ctx, jti) }
    authRedisExists = func(_ *data.Redis, ctx context.Context, key string) (int64, error) { if _,ok:=rd.kv[key]; ok { return 1,nil }; return 0,nil }
    authRedisGet = func(_ *data.Redis, ctx context.Context, key string) (string, error) { return rd.kv[key], nil }
    authRedisSet = func(_ *data.Redis, ctx context.Context, key, value string, ttl time.Duration) error { rd.kv[key] = value; return nil }
    authRedisDel = func(_ *data.Redis, ctx context.Context, key string) error { delete(rd.kv, key); return nil }
    authDbRevokeToken = func(_ *data.Postgres, ctx context.Context, jti, reason string) error { return db.RevokeToken(ctx, jti, reason) }
    
    tok, jti, _, _ := v.Issue(nil, "p1", time.Minute, "", "")
    
    // After Issue, token is already in cache. Clear cache to test DB lookup
    rd.kv = map[string]string{}
    
    // First verify (no cache): should hit DB
    dbLookups = 0
    if _, _, _, err := v.Verify(nil, tok); err != nil { t.Fatalf("first verify: %v", err) }
    if dbLookups != 1 { t.Fatalf("expected 1 db lookup, got %d", dbLookups) }
    
    // Second verify (with cache): should hit Redis cache (no DB lookup)
    dbLookups = 0
    if _, _, _, err := v.Verify(nil, tok); err != nil { t.Fatalf("second verify: %v", err) }
    if dbLookups != 0 { t.Fatalf("expected 0 db lookups on cache hit, got %d", dbLookups) }
    
    // Now revoke and verify cache is cleared
    _ = v.Revoke(nil, jti, "test")
    
    // Verify after revoke should hit Redis revocation cache immediately
    if _, _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("should reject revoked token") }
}

func TestVerify_SSHPublicKeyFormats(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    
    // Generate SSH public key in OpenSSH format
    sshPub, _ := ssh.NewPublicKey(pub)
    sshPubLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(sshPub.Marshal())
    
    cfg := kernelcfg.AuthConfig{
        RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k",
        PublicKeysSSH: map[string]string{"ssh-k": sshPubLine},
        PrivateKey: b64raw(priv),
        CacheTTLSeconds: 60, SkewSeconds: 60,
    }
    v, err := NewVerifier(cfg, nil, nil)
    if err != nil { t.Fatalf("new verifier: %v", err) }
    if len(v.pub) != 1 { t.Fatalf("expected 1 public key from SSH format") }
}

func TestRevoke_TokenAndCacheInvalidation(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{RequireToken: true, Issuer: "iss", Audience: "aud", KeyID: "k", PublicKeys: map[string]string{"k": b64raw(pub)}, PrivateKey: b64raw(priv), CacheTTLSeconds: 60, SkewSeconds: 60}
    v, _ := NewVerifier(cfg, nil, nil)
    
    db := &fakeDB{exists: true, pid: "p1", revoked: false}
    rd := &fakeRedis{kv: map[string]string{}}
    
    authDbInsertToken = func(_ *data.Postgres, ctx context.Context, producerID, jti string, exp time.Time, notes string) error { return db.InsertProducerToken(ctx, producerID, jti, exp, notes) }
    authDbTokenExists = func(_ *data.Postgres, ctx context.Context, jti string) (bool, string) { return db.TokenExists(ctx, jti) }
    authDbIsTokenRevoked = func(_ *data.Postgres, ctx context.Context, jti string) bool { return db.IsTokenRevoked(ctx, jti) }
    authDbRevokeToken = func(_ *data.Postgres, ctx context.Context, jti, reason string) error { return db.RevokeToken(ctx, jti, reason) }
    authRedisExists = func(_ *data.Redis, ctx context.Context, key string) (int64, error) { if _,ok:=rd.kv[key]; ok { return 1,nil }; return 0,nil }
    authRedisGet = func(_ *data.Redis, ctx context.Context, key string) (string, error) { return rd.kv[key], nil }
    authRedisSet = func(_ *data.Redis, ctx context.Context, key, value string, ttl time.Duration) error { rd.kv[key] = value; return nil }
    authRedisDel = func(_ *data.Redis, ctx context.Context, key string) error { delete(rd.kv, key); return nil }
    
    tok, jti, _, _ := v.Issue(nil, "p1", time.Minute, "", "fp")
    
    // Verify works
    if _, _, _, err := v.Verify(nil, tok); err != nil { t.Fatalf("verify before revoke: %v", err) }
    
    // Revoke should clear auth cache and set revoked flag
    if err := v.Revoke(nil, jti, "test revoke"); err != nil { t.Fatalf("revoke: %v", err) }
    
    // Verify fails now
    if _, _, _, err := v.Verify(nil, tok); err == nil { t.Fatalf("verify after revoke should fail") }
    
    // Redis should have revocation marker
    if _, ok := rd.kv["revoked:jti:"+jti]; !ok { t.Fatalf("revoked:jti key not in cache") }
    // Auth cache should be cleared
    if _, ok := rd.kv["auth:jti:"+jti]; ok { t.Fatalf("auth:jti should be cleared after revoke") }
}


