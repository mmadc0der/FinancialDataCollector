package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/sha3"
	ssh "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
    
    "github.com/example/data-kernel/internal/logging"
)

// Minimal JWT-like structs for debug logging of tokens
type jwtHeader struct {
    Alg string `json:"alg"`
    Kid string `json:"kid"`
    Typ string `json:"typ"`
}

type jwtClaims struct {
    Iss string `json:"iss"`
    Aud string `json:"aud"`
    Sub string `json:"sub"`
    Sid string `json:"sid"`
    Iat int64  `json:"iat"`
    Nbf int64  `json:"nbf"`
    Exp int64  `json:"exp"`
    Jti string `json:"jti"`
    Fp  string `json:"fp"`
}

func parseTokenUnsafe(tok string) (jwtHeader, jwtClaims, error) {
    var h jwtHeader
    var c jwtClaims
    parts := strings.Split(tok, ".")
    if len(parts) != 3 { return h, c, fmt.Errorf("bad_token_format") }
    hb, err := base64.RawURLEncoding.DecodeString(parts[0])
    if err != nil { return h, c, fmt.Errorf("bad_header_b64: %w", err) }
    cb, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil { return h, c, fmt.Errorf("bad_claims_b64: %w", err) }
    if err := json.Unmarshal(hb, &h); err != nil { return h, c, fmt.Errorf("bad_header_json: %w", err) }
    if err := json.Unmarshal(cb, &c); err != nil { return h, c, fmt.Errorf("bad_claims_json: %w", err) }
    return h, c, nil
}

func tokenPreview(tok string) string {
    if len(tok) > 24 { return tok[:24] + "..." }
    return tok
}

type Config struct {
    Redis struct {
        Addr       string `yaml:"addr"`
        Username   string `yaml:"username"`
        Password   string `yaml:"password"`
        DB         int    `yaml:"db"`
        KeyPrefix  string `yaml:"key_prefix"`
    } `yaml:"redis"`
    Producer struct {
        Name          string `yaml:"name"`
        Contact       string `yaml:"contact"`
        SendIntervalMs int   `yaml:"send_interval_ms"`
        SSHPrivateKeyFile string `yaml:"ssh_private_key_file"`
        SSHPublicKeyFile  string `yaml:"ssh_public_key_file"`
        SSHCertFile       string `yaml:"ssh_cert_file"`
        SubjectKey        string `yaml:"subject_key"`
        ProducerID        string `yaml:"producer_id"` // optional for key rotation
        SchemaID          string `yaml:"schema_id"`
        SchemaName        string `yaml:"schema_name"`
        SchemaVersion     int    `yaml:"schema_version"`
        SchemaBody        string `yaml:"schema_body"`
    } `yaml:"producer"`
}

func loadConfig(path string) Config {
    ev := logging.NewEventLogger()
    b, err := os.ReadFile(path)
    if err != nil { ev.Infra("config", "producer", "failed", "read_config_error: "+err.Error()); os.Exit(1) }
    var c Config
    if err := yaml.Unmarshal(b, &c); err != nil { ev.Infra("config", "producer", "failed", "yaml_unmarshal_error: "+err.Error()); os.Exit(1) }
    return c
}

func canonicalJSON(v any) string {
    b, _ := json.Marshal(v)
    return string(b)
}

func computeFingerprint(pubLine string) string {
    sum := sha3.Sum512([]byte(pubLine))
    return base64.StdEncoding.EncodeToString(sum[:])
}

func readTrim(path string) (string, error) {
    b, err := os.ReadFile(path)
    if err != nil { return "", err }
    return strings.TrimSpace(string(b)), nil
}

func loadSignerFromKeyFile(path string) (ssh.Signer, error) {
    pem, err := os.ReadFile(path)
    if err != nil { return nil, err }
    var s ssh.Signer
    if passFile := os.Getenv("PRODUCER_SSH_PASSPHRASE_FILE"); passFile != "" {
        if pass, e := os.ReadFile(passFile); e == nil {
            s, err = ssh.ParsePrivateKeyWithPassphrase(pem, bytes.TrimSpace(pass))
        } else {
            err = e
        }
    } else {
        s, err = ssh.ParsePrivateKey(pem)
    }
    if err != nil { return nil, err }
    if s.PublicKey().Type() != ssh.KeyAlgoED25519 {
        return nil, fmt.Errorf("unsupported private key type (need ed25519)")
    }
    return s, nil
}

func randNonce() (string, error) {
    b := make([]byte, 16)
    if _, err := rand.Read(b); err != nil { return "", err }
    // URL-safe, no padding
    return base64.RawURLEncoding.EncodeToString(b), nil
}

func signPayloadNonce(signer ssh.Signer, payloadStr, nonce string) (string, error) {
    // Ed25519-only: sign raw canonical bytes (no prehash)
    msg := []byte(payloadStr + "." + nonce)
    sshSig, err := signer.Sign(rand.Reader, msg)
    if err != nil { return "", err }
    if signer.PublicKey().Type() != ssh.KeyAlgoED25519 || len(sshSig.Blob) != ed25519.SignatureSize {
        return "", fmt.Errorf("sign_error: unsupported signer or signature size")
    }
    return base64.StdEncoding.EncodeToString(sshSig.Blob), nil
}

// readResponseOnce reads ONE message from a response stream, tracking position to avoid stale messages.
// This prevents reading old expired tokens from stream start ("0").
// On first call (lastID == ""), reads from "$" (new messages only).
// On subsequent calls, reads from after lastID.
func readResponseOnce(ctx context.Context, rdb *redis.Client, stream string, lastID string, block time.Duration) (redis.XMessage, string, error) {
    startID := lastID
    if startID == "" {
        // First call: Start from new messages only (not from stream beginning)
        // "$" means "only messages added after this read starts"
        // Use blocking read to wait for first message
        startID = "$"
    }
    
    for ctx.Err() == nil {
        res, err := rdb.XRead(ctx, &redis.XReadArgs{
            Streams: []string{stream, startID},
            Count:   1,
            Block:   block,
        }).Result()
        if err == redis.Nil { 
            // No new messages yet, but could be a timeout - continue waiting
            continue 
        }
        if err != nil { 
            return redis.XMessage{}, "", err 
        }
        for _, s := range res {
            if len(s.Messages) > 0 {
                msg := s.Messages[0]
                // Return message and its ID so caller can track position
                return msg, msg.ID, nil
            }
        }
    }
    return redis.XMessage{}, "", ctx.Err()
}

// sendSubjectOpSigned sends a signed subject operation and waits for a response.
// It retries with a fresh nonce and signature on timeout to avoid nonce replays.
func sendSubjectOpSigned(ctx context.Context, rdb *redis.Client, signer ssh.Signer, pubForRegistration string, cfg Config, producerID string) (string, string, int, error) {
    ev := logging.NewEventLogger()
    subjectKey := cfg.Producer.SubjectKey
    if subjectKey == "" { subjectKey = "DEMO-1" }
    // Always use register operation - it's idempotent and will create subject/schema if needed
    // Register operation requires both schema_name and schema_body
    schemaName := cfg.Producer.SchemaName
    if schemaName == "" { schemaName = "demo_schema" }
    
    schemaBody := cfg.Producer.SchemaBody
    if schemaBody == "" { 
        schemaBody = `{"type":"object","properties":{"value":{"type":"number"},"timestamp":{"type":"string"}},"required":["value","timestamp"]}`
    }
    
    baseReq := map[string]any{
        "op": "register", 
        "subject_key": subjectKey, 
        "attrs": map[string]any{"region":"eu"},
        "schema_name": schemaName,
        "schema_body": schemaBody,
    }

    subjStream := cfg.Redis.KeyPrefix+"subject:register"
    subjRespStream := cfg.Redis.KeyPrefix+"subject:resp:"+producerID
    var lastRespID string

    attempts := 3
    backoff := 3 * time.Second
    for i := 1; i <= attempts; i++ {
        payload := canonicalJSON(baseReq)
        nonce, e := randNonce(); if e != nil { return "", "", 0, e }
        sig, e := signPayloadNonce(signer, payload, nonce); if e != nil { return "", "", 0, e }
        if sid, se := rdb.XAdd(ctx, &redis.XAddArgs{Stream: subjStream, Values: map[string]any{"pubkey": pubForRegistration, "payload": payload, "nonce": nonce, "sig": sig}}).Result(); se == nil {
            ev.Infra("write", "redis", "success", fmt.Sprintf("subject_register_sent attempt=%d id=%s stream=%s subject_key=%s op=%v", i, sid, subjStream, subjectKey, baseReq["op"])) 
        } else {
            return "", "", 0, se
        }
        // wait for response
        msg, newID, e := readResponseOnce(ctx, rdb, subjRespStream, lastRespID, 15*time.Second)
        if e == nil && len(msg.Values) > 0 {
            lastRespID = newID
            var subjectID string
            var schemaID string
            var version int
            if v, ok := msg.Values["subject_id"].(string); ok { subjectID = v }
            if v, ok := msg.Values["schema_id"].(string); ok { schemaID = v }
            switch vv := msg.Values["schema_version"].(type) {
            case int64:
                version = int(vv)
            case int:
                version = vv
            case string:
                // best-effort parse; ignore error
                if n, err := fmt.Sscanf(vv, "%d", &version); n == 1 && err == nil { /* parsed */ }
            }
            if subjectID != "" { return subjectID, schemaID, version, nil }
        }
        // timeout or no response: backoff then retry with fresh nonce/signature
        time.Sleep(backoff)
        if backoff < 10*time.Second { backoff *= 2 }
    }
    return "", "", 0, fmt.Errorf("subject op timeout after retries")
}

func main() {
    cfgPath := flag.String("config", "modules.d/producer-example/config.yaml", "path to config file")
    overrideInt := flag.Int("interval_ms", 0, "override send interval in ms")
    flag.Parse()

    cfg := loadConfig(*cfgPath)
    if *overrideInt > 0 { cfg.Producer.SendIntervalMs = *overrideInt }

    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    ev := logging.NewEventLogger()
    rdb := redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB})
    if err := rdb.Ping(ctx).Err(); err != nil { ev.Infra("connect", "redis", "failed", fmt.Sprintf("ping_error: %v", err)); os.Exit(1) }
    ev.Infra("start", "producer", "success", fmt.Sprintf("addr=%s prefix=%s interval_ms=%d", cfg.Redis.Addr, cfg.Redis.KeyPrefix, cfg.Producer.SendIntervalMs))

    // Load keys and cert (required)
    if cfg.Producer.SSHPublicKeyFile == "" || cfg.Producer.SSHPrivateKeyFile == "" || cfg.Producer.SSHCertFile == "" {
        ev.Infra("config", "producer", "failed", "missing required key/cert files: ssh_private_key_file, ssh_public_key_file, ssh_cert_file must be set"); os.Exit(1)
    }
    var signer ssh.Signer
    if _, err := readTrim(cfg.Producer.SSHPublicKeyFile); err != nil { ev.Infra("config", "producer", "failed", fmt.Sprintf("read_public_key: %v", err)); os.Exit(1) }
    if s, err := loadSignerFromKeyFile(cfg.Producer.SSHPrivateKeyFile); err == nil { signer = s } else { ev.Infra("config", "producer", "failed", fmt.Sprintf("read_private_key_signer: %v", err)); os.Exit(1) }
    // Send cert line as pubkey in registration (server unwraps cert and enforces CA)
    pubForRegistration := func() string {
        certLine, e := readTrim(cfg.Producer.SSHCertFile)
        if e == nil { return certLine }
        ev.Infra("config", "producer", "failed", fmt.Sprintf("read_cert_file: %v", e)); os.Exit(1)
        return ""
    }()
    // fingerprint is not used client-side; server computes and matches as needed
    fp := computeFingerprint(pubForRegistration)
    ev.Infra("init", "producer", "success", fmt.Sprintf("registration_prepare fingerprint=%s pubkey_len=%d", fp, len(pubForRegistration)))

    // send registration (repeat until producer_id acquired)
    payload := map[string]any{
        "producer_hint": cfg.Producer.Name, 
        "contact": cfg.Producer.Contact, 
        "meta": map[string]string{"demo":"true"},
    }
    // Add producer_id for key rotation if configured
    if cfg.Producer.ProducerID != "" {
        payload["producer_id"] = cfg.Producer.ProducerID
    }
    payloadStr := canonicalJSON(payload)
    regStream := cfg.Redis.KeyPrefix + "register"
    // Send registration ONCE, then wait on the same response stream until approved/denied
    var producerID string
    nonce, e := randNonce(); if e != nil { ev.Infra("init", "producer", "failed", fmt.Sprintf("nonce_error: %v", e)); os.Exit(1) }
    ev.Infra("init", "producer", "success", fmt.Sprintf("registration_signing stream=%s nonce=%s payload_len=%d", regStream, nonce, len(payloadStr)))
    sigB64, e := signPayloadNonce(signer, payloadStr, nonce); if e != nil { ev.Infra("init", "producer", "failed", fmt.Sprintf("sign_error: %v", e)); os.Exit(1) }
    if id, e := rdb.XAdd(ctx, &redis.XAddArgs{Stream: regStream, Values: map[string]any{"pubkey": pubForRegistration, "payload": payloadStr, "nonce": nonce, "sig": sigB64}}).Result(); e == nil {
        ev.Infra("write", "redis", "success", fmt.Sprintf("register_sent id=%s stream=%s fp=%s", id, regStream, fp))
    } else { ev.Infra("write", "redis", "failed", fmt.Sprintf("register_send_error: %v", e)); os.Exit(1) }
    respStream := cfg.Redis.KeyPrefix + "register:resp:" + nonce
    ev.Infra("read", "redis", "success", fmt.Sprintf("registration_waiting resp_stream=%s", respStream))
    for producerID == "" {
        if msg, _, e := readResponseOnce(ctx, rdb, respStream, "", 60*time.Second); e == nil {
            ev.Infra("read", "redis", "success", fmt.Sprintf("registration_response id=%s values=%v", msg.ID, msg.Values))
            if pid, ok := msg.Values["producer_id"].(string); ok { producerID = pid }
            if status, ok := msg.Values["status"].(string); ok {
                switch status {
                case "approved":
                    ev.Infra("read", "redis", "success", fmt.Sprintf("registration_approved producer_id=%s fp=%s", producerID, fp))
                case "pending":
                    // keep waiting for admin approval notification pushed by kernel
                    if producerID != "" { ev.Infra("read", "redis", "success", fmt.Sprintf("registration_pending producer_id=%s", producerID)) } else { ev.Infra("read", "redis", "success", "registration_pending") }
                case "denied", "invalid_sig", "invalid_cert":
                    if reason, ok := msg.Values["reason"].(string); ok {
                        ev.Infra("read", "redis", "failed", fmt.Sprintf("registration_denied status=%s reason=%s", status, reason))
                    } else {
                        ev.Infra("read", "redis", "failed", fmt.Sprintf("registration_denied status=%s", status))
                    }
                    os.Exit(1)
                }
            }
        } else if e == context.DeadlineExceeded || e == context.Canceled {
            // continue waiting unless canceled
            if e == context.Canceled { return }
        }
    }
    ev.Infra("init", "producer", "success", fmt.Sprintf("registered producer_id=%s fp=%s", producerID, fp))

    // token exchange: request short-lived token using pubkey path
    exchPayload := canonicalJSON(map[string]any{"purpose":"exchange"})
    nonceEx, e := randNonce(); if e != nil { ev.Infra("init", "producer", "failed", fmt.Sprintf("nonce_error: %v", e)); os.Exit(1) }
    sigEx, e := signPayloadNonce(signer, exchPayload, nonceEx); if e != nil { ev.Infra("init", "producer", "failed", fmt.Sprintf("sign_error: %v", e)); os.Exit(1) }
    exchStream := cfg.Redis.KeyPrefix+"token:exchange"
    if xid, xe := rdb.XAdd(ctx, &redis.XAddArgs{Stream: exchStream, Values: map[string]any{"pubkey": pubForRegistration, "payload": exchPayload, "nonce": nonceEx, "sig": sigEx}}).Result(); xe == nil {
        ev.Infra("write", "redis", "success", fmt.Sprintf("token_exchange_sent id=%s stream=%s nonce=%s fp=%s", xid, exchStream, nonceEx, fp))
    } else {
        ev.Infra("write", "redis", "failed", fmt.Sprintf("token_exchange_send_error: %v", xe)); os.Exit(1)
    }
    // wait on per-producer token response - read from new messages only
    var lastTokenID string
    tokenRespStream := cfg.Redis.KeyPrefix+"token:resp:"+producerID
    ev.Infra("read", "redis", "success", fmt.Sprintf("token_exchange_waiting resp_stream=%s", tokenRespStream))
    tokMsg, lastTokenID, e := readResponseOnce(ctx, rdb, tokenRespStream, lastTokenID, 15*time.Second)
    if e != nil { ev.Infra("read", "redis", "failed", fmt.Sprintf("token_exchange_timeout: %v", e)); os.Exit(1) }
    ev.Infra("read", "redis", "success", fmt.Sprintf("token_exchange_response id=%s values=%v", tokMsg.ID, tokMsg.Values))
    token, _ := tokMsg.Values["token"].(string)
    if token == "" { ev.Infra("read", "redis", "failed", "token_exchange_empty"); os.Exit(1) }
    if h, c, pe := parseTokenUnsafe(token); pe == nil {
        exp := time.Unix(c.Exp, 0).UTC().Format(time.RFC3339Nano)
        ev.Infra("init", "producer", "success", fmt.Sprintf("token_received producer_id=%s jti=%s kid=%s exp=%s fp=%s preview=%s", producerID, c.Jti, h.Kid, exp, c.Fp, tokenPreview(token)))
    } else {
        ev.Infra("init", "producer", "success", fmt.Sprintf("token_received producer_id=%s token_len=%d preview=%s", producerID, len(token), tokenPreview(token)))
    }

    // subject set_current: signed op on subject:register
    subjectID, schemaIDFromResp, version, e := sendSubjectOpSigned(ctx, rdb, signer, pubForRegistration, cfg, producerID)
    if e != nil { ev.Infra("write", "redis", "failed", fmt.Sprintf("subject_register_error: %v", e)); os.Exit(1) }
    if schemaIDFromResp != "" { cfg.Producer.SchemaID = schemaIDFromResp }
    if version > 0 {
        ev.Infra("write", "redis", "success", fmt.Sprintf("subject_provisioned subject_id=%s schema_id=%s version=%d", subjectID, cfg.Producer.SchemaID, version))
    } else {
        ev.Infra("write", "redis", "success", fmt.Sprintf("subject_provisioned subject_id=%s schema_id=%s", subjectID, cfg.Producer.SchemaID))
    }

    // dedicated schema upgrade: send only if schema_name and schema_body provided
    if strings.TrimSpace(cfg.Producer.SchemaName) != "" && strings.TrimSpace(cfg.Producer.SchemaBody) != "" {
        upReq := map[string]any{
            "subject_key": cfg.Producer.SubjectKey,
            "schema_name": cfg.Producer.SchemaName,
            "schema_body": json.RawMessage(cfg.Producer.SchemaBody),
        }
        upPayload := canonicalJSON(upReq)
        upNonce, e := randNonce(); if e != nil { ev.Infra("init", "producer", "failed", fmt.Sprintf("nonce_error: %v", e)); os.Exit(1) }
        upSig, e := signPayloadNonce(signer, upPayload, upNonce); if e != nil { ev.Infra("init", "producer", "failed", fmt.Sprintf("sign_error: %v", e)); os.Exit(1) }
        upStream := cfg.Redis.KeyPrefix+"schema:upgrade"
        if uid, ue := rdb.XAdd(ctx, &redis.XAddArgs{Stream: upStream, Values: map[string]any{"pubkey": pubForRegistration, "payload": upPayload, "nonce": upNonce, "sig": upSig}}).Result(); ue == nil {
            ev.Infra("write", "redis", "success", fmt.Sprintf("schema_upgrade_sent id=%s stream=%s", uid, upStream))
        } else {
            ev.Infra("write", "redis", "failed", fmt.Sprintf("schema_upgrade_send_error: %v", ue))
        }
    }

    // periodically send demo events with token
    interval := time.Duration(cfg.Producer.SendIntervalMs) * time.Millisecond
    if interval <= 0 { interval = time.Second }
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    eventsSent := 0
    for {
        select {
        case <-ticker.C:
            // lean event payload
            // UUIDv7 event id for time-ordered ingestion
            eid, _ := uuid.NewV7()
            eventObj := map[string]any{"event_id": eid.String(), "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": subjectID, "payload": map[string]any{"kind":"status","source": cfg.Producer.Name, "symbol":"DEMO"}}
            evB, _ := json.Marshal(eventObj)
            id, err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"events", Values: map[string]any{"id": eventObj["event_id"], "payload": string(evB), "token": token}}).Result()
            if err != nil { 
                ev.Infra("write", "redis", "failed", fmt.Sprintf("event_xadd_error: %v", err)) 
            } else { 
                eventsSent++
                if eventsSent == 1 {
                    logging.NewEventLogger().Infra("write", "redis", "success", fmt.Sprintf("event_sending_started events_total=1 id=%s", id))
                } else if eventsSent % 1000 == 0 {
                    logging.NewEventLogger().Infra("write", "redis", "success", fmt.Sprintf("event_sent_progress events_total=%d id=%s", eventsSent, id))
                }
            }
        case <-ctx.Done():
            ev.Infra("disconnect", "producer", "success", "producer_stop")
            // send deregister on shutdown
			if nonce, e := randNonce(); e == nil {
				// Sign the exact payload we send; kernel verifies signature over payload+nonce
				deregPayload := canonicalJSON(map[string]any{"reason":"shutdown"})
				if sig, e2 := signPayloadNonce(signer, deregPayload, nonce); e2 == nil {
					_, _ = rdb.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"register", Values: map[string]any{"action":"deregister", "pubkey": pubForRegistration, "payload": deregPayload, "nonce": nonce, "sig": sig}}).Result()
					// optionally wait brief confirm
					_, _, _ = readResponseOnce(context.Background(), rdb, cfg.Redis.KeyPrefix+"register:resp:"+nonce, "", 3*time.Second)
				}
			}
            return
        }
    }
}


