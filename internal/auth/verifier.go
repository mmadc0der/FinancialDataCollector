package auth

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "strings"
    "time"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/logging"
    ulid "github.com/oklog/ulid/v2"
    ssh "golang.org/x/crypto/ssh"
)

type Verifier struct {
    cfg      kernelcfg.AuthConfig
    pub      map[string]ed25519.PublicKey
    priv     ed25519.PrivateKey
    signer   ssh.Signer
    pg       *data.Postgres
    rd       *data.Redis
    cacheTTL time.Duration
    skew     time.Duration
}

func NewVerifier(cfg kernelcfg.AuthConfig, pg *data.Postgres, rd *data.Redis) (*Verifier, error) {
    v := &Verifier{cfg: cfg, pg: pg, rd: rd, cacheTTL: time.Duration(cfg.CacheTTLSeconds) * time.Second, skew: time.Duration(cfg.SkewSeconds) * time.Second}
    v.pub = make(map[string]ed25519.PublicKey, len(cfg.PublicKeys)+len(cfg.PublicKeysSSH))
    for kid, b64 := range cfg.PublicKeys {
        pk, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(b64))
        if err != nil { return nil, fmt.Errorf("invalid public key for %s: %w", kid, err) }
        if len(pk) != ed25519.PublicKeySize { return nil, fmt.Errorf("public key %s wrong size", kid) }
        v.pub[kid] = ed25519.PublicKey(pk)
    }
    for kid, line := range cfg.PublicKeysSSH {
        pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
        if err != nil { return nil, fmt.Errorf("invalid ssh public key for %s: %w", kid, err) }
        if cp, ok := pub.(ssh.CryptoPublicKey); ok {
            if ed, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(ed) == ed25519.PublicKeySize {
                v.pub[kid] = ed
            } else { return nil, fmt.Errorf("ssh public key for %s not ed25519", kid) }
        } else { return nil, fmt.Errorf("ssh public key for %s not crypto", kid) }
    }
    if cfg.PrivateKey != "" {
        sk, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(cfg.PrivateKey))
        if err != nil { return nil, fmt.Errorf("invalid private key: %w", err) }
        if len(sk) != ed25519.PrivateKeySize { return nil, errors.New("private key wrong size") }
        v.priv = ed25519.PrivateKey(sk)
    } else if cfg.PrivateKeyFile != "" {
        pem, err := os.ReadFile(cfg.PrivateKeyFile)
        if err != nil { return nil, fmt.Errorf("read private_key_file: %w", err) }
        var signer ssh.Signer
        if cfg.PrivateKeyPassphraseFile != "" {
            pass, e := os.ReadFile(cfg.PrivateKeyPassphraseFile)
            if e != nil { return nil, fmt.Errorf("read private_key_passphrase_file: %w", e) }
            signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, bytes.TrimSpace(pass))
        } else {
            signer, err = ssh.ParsePrivateKey(pem)
        }
        if err != nil { return nil, fmt.Errorf("parse private_key_file: %w", err) }
        if signer.PublicKey().Type() != ssh.KeyAlgoED25519 { return nil, errors.New("unsupported private key type (need ed25519)") }
        v.signer = signer
    }
    return v, nil
}

type header struct {
    Alg string `json:"alg"`
    Kid string `json:"kid"`
    Typ string `json:"typ"`
}

type claims struct {
    Iss string `json:"iss"`
    Aud string `json:"aud"`
    Sub string `json:"sub"`
    Sid string `json:"sid,omitempty"`
    Iat int64  `json:"iat"`
    Nbf int64  `json:"nbf"`
    Exp int64  `json:"exp"`
    Jti string `json:"jti"`
    Fp  string `json:"fp,omitempty"`
}

func b64url(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
func parseB64(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }

// Issue signs a token for a producer (if private key configured) and records JTI.
// Optionally binds the token to a producer key fingerprint (fp).
func (v *Verifier) Issue(ctx context.Context, producerID string, ttl time.Duration, notes string, fp string) (string, string, time.Time, error) {
    ev := logging.NewEventLogger()
    
    if len(v.priv) == 0 && v.signer == nil {
        return "", "", time.Time{}, errors.New("issuer private key not configured")
    }
    now := time.Now().UTC()
    exp := now.Add(ttl)
    jti := ulid.Make().String()
    hdr := header{Alg: "EdDSA", Kid: v.cfg.KeyID, Typ: "FDC"}
    cl := claims{Iss: v.cfg.Issuer, Aud: v.cfg.Audience, Sub: producerID, Iat: now.Unix(), Nbf: now.Unix() - int64(v.cfg.SkewSeconds), Exp: exp.Unix(), Jti: jti, Fp: fp}
    hb, _ := json.Marshal(hdr)
    cb, _ := json.Marshal(cl)
    signing := b64url(hb) + "." + b64url(cb)
    var sigRaw []byte
    if len(v.priv) > 0 {
        sigRaw = ed25519.Sign(v.priv, []byte(signing))
    } else {
        sshSig, err := v.signer.Sign(rand.Reader, []byte(signing))
        if err != nil { return "", "", time.Time{}, err }
        sigRaw = sshSig.Blob
    }
    tok := signing + "." + b64url(sigRaw)
    if err := authDbInsertToken(v.pg, ctx, producerID, jti, exp, notes); err != nil {
        ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to insert token: %v", err))
    }
    // cache JTI in Redis for fast validation
    if ttl := time.Until(exp); ttl > 0 { _ = authRedisSet(v.rd, ctx, "auth:jti:"+jti, producerID+"|"+fp, ttl) }
    ev.Token("issue", producerID, "", jti, true, "")
    return tok, jti, exp, nil
}

// IssueSubject issues a subject-scoped token by embedding sid.
func (v *Verifier) IssueSubject(ctx context.Context, producerID, subjectID string, ttl time.Duration, notes string, fp string) (string, string, time.Time, error) {
    ev := logging.NewEventLogger()
    
    if len(v.priv) == 0 && v.signer == nil {
        return "", "", time.Time{}, errors.New("issuer private key not configured")
    }
    now := time.Now().UTC()
    exp := now.Add(ttl)
    jti := ulid.Make().String()
    hdr := header{Alg: "EdDSA", Kid: v.cfg.KeyID, Typ: "FDC"}
    cl := claims{Iss: v.cfg.Issuer, Aud: v.cfg.Audience, Sub: producerID, Sid: subjectID, Iat: now.Unix(), Nbf: now.Unix() - int64(v.cfg.SkewSeconds), Exp: exp.Unix(), Jti: jti, Fp: fp}
    hb, _ := json.Marshal(hdr)
    cb, _ := json.Marshal(cl)
    signing := b64url(hb) + "." + b64url(cb)
    var sigRaw []byte
    if len(v.priv) > 0 {
        sigRaw = ed25519.Sign(v.priv, []byte(signing))
    } else {
        sshSig, err := v.signer.Sign(rand.Reader, []byte(signing))
        if err != nil { return "", "", time.Time{}, err }
        sigRaw = sshSig.Blob
    }
    tok := signing + "." + b64url(sigRaw)
    _ = authDbInsertToken(v.pg, ctx, producerID, jti, exp, notes)
    if ttl := time.Until(exp); ttl > 0 { _ = authRedisSet(v.rd, ctx, "auth:jti:"+jti, producerID+"|"+fp, ttl) }
    ev.Token("issue", producerID, subjectID, jti, true, "")
    return tok, jti, exp, nil
}

// Verify validates token signature and basic claims; DB must know the JTI and not be revoked.
func (v *Verifier) Verify(ctx context.Context, tok string) (string, string, string, error) {
    ev := logging.NewEventLogger()
    
    if tok == "" {
        return "", "", "", errors.New("auth_required")
    }
    parts := strings.Split(tok, ".")
    if len(parts) != 3 { return "", "", "", errors.New("bad_token_format") }
    hb, err := parseB64(parts[0])
    if err != nil { return "", "", "", errors.New("bad_header_b64") }
    cb, err := parseB64(parts[1])
    if err != nil { return "", "", "", errors.New("bad_claims_b64") }
    sig, err := parseB64(parts[2])
    if err != nil { return "", "", "", errors.New("bad_sig_b64") }
    var h header
    if err := json.Unmarshal(hb, &h); err != nil { return "", "", "", errors.New("bad_header_json") }
    if h.Alg != "EdDSA" { return "", "", "", errors.New("alg_not_supported") }
    pub := v.pub[h.Kid]
    if len(pub) == 0 { return "", "", "", errors.New("unknown_kid") }
    signing := parts[0] + "." + parts[1]
    if !ed25519.Verify(pub, []byte(signing), sig) { return "", "", "", errors.New("bad_signature") }
    var c claims
    if err := json.Unmarshal(cb, &c); err != nil { return "", "", "", errors.New("bad_claims_json") }
    now := time.Now().UTC().Unix()
    if c.Iss != v.cfg.Issuer || c.Aud != v.cfg.Audience { return "", "", "", errors.New("bad_issuer_audience") }
    if c.Nbf > now+int64(v.cfg.SkewSeconds) { return "", "", "", errors.New("token_not_yet_valid") }
    if c.Exp < now-int64(v.cfg.SkewSeconds) { return "", "", "", errors.New("token_expired") }
    // Redis cache: fast revoke check
    if ok, _ := authRedisExists(v.rd, ctx, "revoked:jti:"+c.Jti); ok > 0 {
        ev.Token("verify", c.Sub, c.Sid, c.Jti, false, "token_revoked")
        return "", "", "", errors.New("token_revoked")
    }
    if s, _ := authRedisGet(v.rd, ctx, "auth:jti:"+c.Jti); s != "" {
        // Optionally validate producer_id match
        if idx := strings.IndexByte(s, '|'); idx > 0 {
            pid := s[:idx]
            if pid == c.Sub { 
                ev.Token("verify", c.Sub, c.Sid, c.Jti, true, "")
                return c.Sub, c.Sid, c.Jti, nil 
            }
        } else if s == c.Sub {
            ev.Token("verify", c.Sub, c.Sid, c.Jti, true, "")
            return c.Sub, c.Sid, c.Jti, nil
        }
    }
    ok, prod := authDbTokenExists(v.pg, ctx, c.Jti)
    if !ok {
        ev.Token("verify", c.Sub, c.Sid, c.Jti, false, "token_not_found")
        return "", "", "", errors.New("unknown_or_mismatched_token")
    }
    if prod != c.Sub {
        ev.Token("verify", c.Sub, c.Sid, c.Jti, false, "producer_mismatch")
        return "", "", "", errors.New("unknown_or_mismatched_token")
    }
    if authDbIsTokenRevoked(v.pg, ctx, c.Jti) { 
        ev.Token("verify", c.Sub, c.Sid, c.Jti, false, "token_revoked_db")
        return "", "", "", errors.New("token_revoked") 
    }
    // Cache allow in Redis for remaining TTL
    if ttl := time.Until(time.Unix(c.Exp, 0)); ttl > 0 { _ = authRedisSet(v.rd, ctx, "auth:jti:"+c.Jti, c.Sub+"|"+c.Fp, ttl) }
    ev.Token("verify", c.Sub, c.Sid, c.Jti, true, "")
    return c.Sub, c.Sid, c.Jti, nil
}

func (v *Verifier) Revoke(ctx context.Context, jti, reason string) error {
    if err := authDbRevokeToken(v.pg, ctx, jti, reason); err != nil { return err }
    _ = authRedisSet(v.rd, ctx, "revoked:jti:"+jti, "1", 30*24*time.Hour)
    _ = authRedisDel(v.rd, ctx, "auth:jti:"+jti)
    return nil
}

// GetKeyStatusWithCache retrieves key status with Redis caching for better performance
func (v *Verifier) GetKeyStatusWithCache(ctx context.Context, fingerprint string) (string, *string, error) {
    // Try cache first
    if status, producerID, found := authKeyStatusGet(v.rd, ctx, fingerprint); found {
        return status, producerID, nil
    }

    // Cache miss - query database
    status, producerID, err := authDbGetKeyStatus(v.pg, ctx, fingerprint)
    if err != nil {
        return "", nil, err
    }

    // Cache the result for 5 minutes (key status doesn't change often)
    _ = authKeyStatusSet(v.rd, ctx, fingerprint, status, producerID, 5*time.Minute)

    return status, producerID, nil
}

// wrapper function for database key status lookup
var authDbGetKeyStatus = func(pg *data.Postgres, ctx context.Context, fingerprint string) (string, *string, error) {
    if pg == nil { return "", nil, errors.New("postgres_disabled") }
    return pg.GetKeyStatus(ctx, fingerprint)
}

// wrapper functions to allow substitution in tests without changing production behavior
var (
    authDbInsertToken = func(pg *data.Postgres, ctx context.Context, producerID, jti string, exp time.Time, notes string) error {
        if pg != nil { return pg.InsertProducerToken(ctx, producerID, jti, exp, notes) }
        return nil
    }
    authDbTokenExists = func(pg *data.Postgres, ctx context.Context, jti string) (bool, string) {
        if pg == nil { return false, "" }
        return pg.TokenExists(ctx, jti)
    }
    authDbIsTokenRevoked = func(pg *data.Postgres, ctx context.Context, jti string) bool {
        if pg == nil { return true }
        return pg.IsTokenRevoked(ctx, jti)
    }
    authDbRevokeToken = func(pg *data.Postgres, ctx context.Context, jti, reason string) error {
        if pg == nil { return errors.New("auth_db_disabled") }
        return pg.RevokeToken(ctx, jti, reason)
    }
    authRedisExists = func(rd *data.Redis, ctx context.Context, key string) (int64, error) {
        if rd != nil && rd.C() != nil { return rd.C().Exists(ctx, key).Result() }
        return 0, nil
    }
    authRedisGet = func(rd *data.Redis, ctx context.Context, key string) (string, error) {
        if rd != nil && rd.C() != nil { return rd.C().Get(ctx, key).Result() }
        return "", nil
    }
    authRedisSet = func(rd *data.Redis, ctx context.Context, key, value string, ttl time.Duration) error {
        if rd != nil && rd.C() != nil { return rd.C().Set(ctx, key, value, ttl).Err() }
        return nil
    }
    authRedisDel = func(rd *data.Redis, ctx context.Context, key string) error {
        if rd != nil && rd.C() != nil { return rd.C().Del(ctx, key).Err() }
        return nil
    }
    // Key status cache helpers
    authKeyStatusGet = func(rd *data.Redis, ctx context.Context, fingerprint string) (string, *string, bool) {
        if rd == nil || rd.C() == nil || fingerprint == "" { return "", nil, false }
        key := "auth:key:status:" + fingerprint
        val, err := rd.C().Get(ctx, key).Result()
        if err == nil && val != "" {
            // Parse cached value: "status|producer_id"
            parts := strings.SplitN(val, "|", 2)
            if len(parts) >= 1 {
                status := parts[0]
                var producerID *string
                if len(parts) > 1 && parts[1] != "" {
                    producerID = &parts[1]
                }
                return status, producerID, true
            }
        }
        return "", nil, false
    }
    authKeyStatusSet = func(rd *data.Redis, ctx context.Context, fingerprint, status string, producerID *string, ttl time.Duration) error {
        if rd == nil || rd.C() == nil || fingerprint == "" { return nil }
        key := "auth:key:status:" + fingerprint
        var val string
        if producerID != nil {
            val = status + "|" + *producerID
        } else {
            val = status + "|"
        }
        return rd.C().Set(ctx, key, val, ttl).Err()
    }
)

