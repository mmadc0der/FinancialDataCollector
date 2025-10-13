package auth

import (
    "context"
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "strings"
    "time"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    ulid "github.com/oklog/ulid/v2"
)

type Verifier struct {
    cfg      kernelcfg.AuthConfig
    pub      map[string]ed25519.PublicKey
    priv     ed25519.PrivateKey
    pg       *data.Postgres
    rd       *data.Redis
    cacheTTL time.Duration
    skew     time.Duration
}

func NewVerifier(cfg kernelcfg.AuthConfig, pg *data.Postgres, rd *data.Redis) (*Verifier, error) {
    v := &Verifier{cfg: cfg, pg: pg, rd: rd, cacheTTL: time.Duration(cfg.CacheTTLSeconds) * time.Second, skew: time.Duration(cfg.SkewSeconds) * time.Second}
    v.pub = make(map[string]ed25519.PublicKey, len(cfg.PublicKeys))
    for kid, b64 := range cfg.PublicKeys {
        pk, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(b64))
        if err != nil { return nil, fmt.Errorf("invalid public key for %s: %w", kid, err) }
        if len(pk) != ed25519.PublicKeySize { return nil, fmt.Errorf("public key %s wrong size", kid) }
        v.pub[kid] = ed25519.PublicKey(pk)
    }
    if cfg.PrivateKey != "" {
        sk, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(cfg.PrivateKey))
        if err != nil { return nil, fmt.Errorf("invalid private key: %w", err) }
        if len(sk) != ed25519.PrivateKeySize { return nil, errors.New("private key wrong size") }
        v.priv = ed25519.PrivateKey(sk)
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
}

func b64url(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
func parseB64(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }

// Issue signs a token for a producer (if private key configured) and records JTI.
func (v *Verifier) Issue(ctx context.Context, producerID string, ttl time.Duration, notes string) (string, string, time.Time, error) {
    if len(v.priv) == 0 {
        return "", "", time.Time{}, errors.New("issuer private key not configured")
    }
    now := time.Now().UTC()
    exp := now.Add(ttl)
    jti := ulid.Make().String()
    hdr := header{Alg: "EdDSA", Kid: v.cfg.KeyID, Typ: "FDC"}
    cl := claims{Iss: v.cfg.Issuer, Aud: v.cfg.Audience, Sub: producerID, Iat: now.Unix(), Nbf: now.Unix() - int64(v.cfg.SkewSeconds), Exp: exp.Unix(), Jti: jti}
    hb, _ := json.Marshal(hdr)
    cb, _ := json.Marshal(cl)
    signing := b64url(hb) + "." + b64url(cb)
    sig := ed25519.Sign(v.priv, []byte(signing))
    tok := signing + "." + b64url(sig)
    if v.pg != nil {
        _ = v.pg.InsertProducerToken(ctx, producerID, jti, exp, notes)
    }
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
    if v.pg == nil { return "", "", errors.New("auth_db_disabled") }
    ok, prod := v.pg.TokenExists(ctx, c.Jti)
    if !ok || prod != c.Sub { return "", "", errors.New("unknown_or_mismatched_token") }
    if v.pg.IsTokenRevoked(ctx, c.Jti) { return "", "", errors.New("token_revoked") }
    return c.Sub, c.Jti, nil
}

func (v *Verifier) Revoke(ctx context.Context, jti, reason string) error {
    if v.pg == nil { return errors.New("auth_db_disabled") }
    return v.pg.RevokeToken(ctx, jti, reason)
}
