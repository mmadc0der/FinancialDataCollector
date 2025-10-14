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
    // test seams (optional overrides)
    dbInsertToken    func(ctx context.Context, producerID, jti string, exp time.Time, notes string) error
    dbTokenExists    func(ctx context.Context, jti string) (bool, string)
    dbIsTokenRevoked func(ctx context.Context, jti string) bool
    dbRevokeToken    func(ctx context.Context, jti, reason string) error
    redisExists      func(ctx context.Context, key string) (int64, error)
    redisGet         func(ctx context.Context, key string) (string, error)
    redisSet         func(ctx context.Context, key, value string, ttl time.Duration) error
    redisDel         func(ctx context.Context, key string) error
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
    // initialize default seams when dependencies present
    if pg != nil {
        v.dbInsertToken = pg.InsertProducerToken
        v.dbTokenExists = pg.TokenExists
        v.dbIsTokenRevoked = pg.IsTokenRevoked
        v.dbRevokeToken = pg.RevokeToken
    }
    if rd != nil && rd.C() != nil {
        v.redisExists = func(ctx context.Context, key string) (int64, error) { return rd.C().Exists(ctx, key).Result() }
        v.redisGet = func(ctx context.Context, key string) (string, error) { return rd.C().Get(ctx, key).Result() }
        v.redisSet = func(ctx context.Context, key, value string, ttl time.Duration) error { return rd.C().Set(ctx, key, value, ttl).Err() }
        v.redisDel = func(ctx context.Context, key string) error { return rd.C().Del(ctx, key).Err() }
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
    if v.dbInsertToken != nil {
        _ = v.dbInsertToken(ctx, producerID, jti, exp, notes)
    }
    // cache JTI in Redis for fast validation
    if v.redisSet != nil {
        ttl := time.Until(exp)
        if ttl > 0 { _ = v.redisSet(ctx, "auth:jti:"+jti, producerID+"|"+fp, ttl) }
    }
    logging.Info("auth_token_issued", logging.F("producer_id", producerID), logging.F("jti", jti), logging.F("fp", fp))
    return tok, jti, exp, nil
}

// Verify validates token signature and basic claims; DB must know the JTI and not be revoked.
func (v *Verifier) Verify(ctx context.Context, tok string) (string, string, error) {
    if !v.cfg.Enabled || !v.cfg.RequireToken || tok == "" {
        return "", "", errors.New("auth_required")
    }
    parts := strings.Split(tok, ".")
    if len(parts) != 3 { return "", "", errors.New("bad_token_format") }
    hb, err := parseB64(parts[0])
    if err != nil { return "", "", errors.New("bad_header_b64") }
    cb, err := parseB64(parts[1])
    if err != nil { return "", "", errors.New("bad_claims_b64") }
    sig, err := parseB64(parts[2])
    if err != nil { return "", "", errors.New("bad_sig_b64") }
    var h header
    if err := json.Unmarshal(hb, &h); err != nil { return "", "", errors.New("bad_header_json") }
    if h.Alg != "EdDSA" { return "", "", errors.New("alg_not_supported") }
    pub := v.pub[h.Kid]
    if len(pub) == 0 { return "", "", errors.New("unknown_kid") }
    signing := parts[0] + "." + parts[1]
    if !ed25519.Verify(pub, []byte(signing), sig) { return "", "", errors.New("bad_signature") }
    var c claims
    if err := json.Unmarshal(cb, &c); err != nil { return "", "", errors.New("bad_claims_json") }
    now := time.Now().UTC().Unix()
    if c.Iss != v.cfg.Issuer || c.Aud != v.cfg.Audience { return "", "", errors.New("bad_issuer_audience") }
    if c.Nbf > now+int64(v.cfg.SkewSeconds) { return "", "", errors.New("token_not_yet_valid") }
    if c.Exp < now-int64(v.cfg.SkewSeconds) { return "", "", errors.New("token_expired") }
    // Redis cache: fast revoke check
    if v.redisExists != nil {
        if ok, _ := v.redisExists(ctx, "revoked:jti:"+c.Jti); ok > 0 {
            return "", "", errors.New("token_revoked")
        }
        if s, _ := v.redisGet(ctx, "auth:jti:"+c.Jti); s != "" {
            // Optionally validate producer_id match
            if idx := strings.IndexByte(s, '|'); idx > 0 {
                pid := s[:idx]
                if pid == c.Sub { return c.Sub, c.Jti, nil }
            } else if s == c.Sub {
                return c.Sub, c.Jti, nil
            }
        }
    }
    if v.dbTokenExists == nil || v.dbIsTokenRevoked == nil { return "", "", errors.New("auth_db_disabled") }
    ok, prod := v.dbTokenExists(ctx, c.Jti)
    if !ok || prod != c.Sub { return "", "", errors.New("unknown_or_mismatched_token") }
    if v.dbIsTokenRevoked(ctx, c.Jti) { return "", "", errors.New("token_revoked") }
    // Cache allow in Redis for remaining TTL
    if v.redisSet != nil {
        ttl := time.Until(time.Unix(c.Exp, 0))
        if ttl > 0 { _ = v.redisSet(ctx, "auth:jti:"+c.Jti, c.Sub+"|"+c.Fp, ttl) }
    }
    return c.Sub, c.Jti, nil
}

func (v *Verifier) Revoke(ctx context.Context, jti, reason string) error {
    if v.dbRevokeToken == nil { return errors.New("auth_db_disabled") }
    if err := v.dbRevokeToken(ctx, jti, reason); err != nil { return err }
    if v.redisSet != nil { _ = v.redisSet(ctx, "revoked:jti:"+jti, "1", 30*24*time.Hour) }
    if v.redisDel != nil { _ = v.redisDel(ctx, "auth:jti:"+jti) }
    return nil
}

