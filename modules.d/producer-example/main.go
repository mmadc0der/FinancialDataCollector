package main

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "flag"
    "fmt"
    "bytes"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    ssh "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/sha3"
    "github.com/redis/go-redis/v9"
    "gopkg.in/yaml.v3"
)

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
    } `yaml:"producer"`
}

func loadConfig(path string) Config {
    b, err := os.ReadFile(path)
    if err != nil { log.Fatal(err) }
    var c Config
    if err := yaml.Unmarshal(b, &c); err != nil { log.Fatal(err) }
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
    sum := sha3.Sum512([]byte(payloadStr + "." + nonce))
    sshSig, err := signer.Sign(rand.Reader, sum[:])
    if err != nil { return "", err }
    if signer.PublicKey().Type() != ssh.KeyAlgoED25519 || len(sshSig.Blob) != ed25519.SignatureSize {
        return "", fmt.Errorf("sign_error: unsupported signer or signature size")
    }
    return base64.StdEncoding.EncodeToString(sshSig.Blob), nil
}

func xreadOne(ctx context.Context, rdb *redis.Client, stream string, block time.Duration) (redis.XMessage, error) {
    // Use XREAD to read new messages from the stream (no consumer groups for response streams)
    for ctx.Err() == nil {
        res, err := rdb.XRead(ctx, &redis.XReadArgs{
            Streams: []string{stream, "0"},
            Count:   1,
            Block:   block,
        }).Result()
        if err == redis.Nil { continue }
        if err != nil { return redis.XMessage{}, err }
        for _, s := range res {
            if len(s.Messages) > 0 {
                return s.Messages[0], nil
            }
        }
    }
    return redis.XMessage{}, ctx.Err()
}

func main() {
    cfgPath := flag.String("config", "modules.d/producer-example/config.yaml", "path to config file")
    overrideInt := flag.Int("interval_ms", 0, "override send interval in ms")
    flag.Parse()

    cfg := loadConfig(*cfgPath)
    if *overrideInt > 0 { cfg.Producer.SendIntervalMs = *overrideInt }

    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    rdb := redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB})
    if err := rdb.Ping(ctx).Err(); err != nil { log.Fatalf("redis_ping_error: %v", err) }
    log.Printf("producer_start addr=%s prefix=%s interval_ms=%d",
        cfg.Redis.Addr, cfg.Redis.KeyPrefix, cfg.Producer.SendIntervalMs)

    // Load keys and cert (required)
    if cfg.Producer.SSHPublicKeyFile == "" || cfg.Producer.SSHPrivateKeyFile == "" || cfg.Producer.SSHCertFile == "" {
        log.Fatalf("missing required key/cert files: ssh_private_key_file, ssh_public_key_file, ssh_cert_file must be set")
    }
    var signer ssh.Signer
    if _, err := readTrim(cfg.Producer.SSHPublicKeyFile); err != nil { log.Fatalf("read_public_key: %v", err) }
    if s, err := loadSignerFromKeyFile(cfg.Producer.SSHPrivateKeyFile); err == nil { signer = s } else { log.Fatalf("read_private_key_signer: %v", err) }
    // Send cert line as pubkey in registration (server unwraps cert and enforces CA)
    pubForRegistration := func() string {
        certLine, e := readTrim(cfg.Producer.SSHCertFile)
        if e == nil { return certLine }
        log.Fatalf("read_cert_file: %v", e)
        return ""
    }()
    // fingerprint is not used client-side; server computes and matches as needed

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
    nonce, e := randNonce(); if e != nil { log.Fatalf("nonce_error: %v", e) }
    sigB64, e := signPayloadNonce(signer, payloadStr, nonce); if e != nil { log.Fatalf("sign_error: %v", e) }
    if id, e := rdb.XAdd(ctx, &redis.XAddArgs{Stream: regStream, Values: map[string]any{"pubkey": pubForRegistration, "payload": payloadStr, "nonce": nonce, "sig": sigB64}}).Result(); e == nil {
        log.Printf("register_sent id=%s", id)
    } else { log.Fatalf("register_send_error: %v", e) }
    respStream := cfg.Redis.KeyPrefix + "register:resp:" + nonce
    for producerID == "" {
        if msg, e := xreadOne(ctx, rdb, respStream, 60*time.Second); e == nil {
            if pid, ok := msg.Values["producer_id"].(string); ok { producerID = pid }
            if status, ok := msg.Values["status"].(string); ok {
                switch status {
                case "approved":
                    log.Printf("registration_approved producer_id=%s", producerID)
                case "pending":
                    // keep waiting for admin approval notification pushed by kernel
                    if producerID != "" { log.Printf("registration_pending producer_id=%s", producerID) } else { log.Printf("registration_pending") }
                case "denied", "invalid_sig", "invalid_cert":
                    if reason, ok := msg.Values["reason"].(string); ok {
                        log.Printf("registration_denied status=%s reason=%s", status, reason)
                    } else {
                        log.Printf("registration_denied status=%s", status)
                    }
                    log.Fatalf("registration_denied: %s", status)
                }
            }
        } else if e == context.DeadlineExceeded || e == context.Canceled {
            // continue waiting unless canceled
            if e == context.Canceled { return }
        }
    }
    log.Printf("registered producer_id=%s", producerID)

    // token exchange: request short-lived token using pubkey path
    exchPayload := canonicalJSON(map[string]any{"purpose":"exchange"})
    nonceEx, e := randNonce(); if e != nil { log.Fatalf("nonce_error: %v", e) }
    sigEx, e := signPayloadNonce(signer, exchPayload, nonceEx); if e != nil { log.Fatalf("sign_error: %v", e) }
    _, _ = rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"token:exchange", Values: map[string]any{"pubkey": pubForRegistration, "payload": exchPayload, "nonce": nonceEx, "sig": sigEx}}).Result()
    // wait on per-producer token response
    tokMsg, e := xreadOne(ctx, rdb, cfg.Redis.KeyPrefix+"token:resp:"+producerID, 15*time.Second)
    if e != nil { log.Fatalf("token_exchange_timeout: %v", e) }
    token, _ := tokMsg.Values["token"].(string)
    if token == "" { log.Fatalf("token_exchange_empty") }
    log.Printf("token_received for producer_id=%s", producerID)

    // subject registration: ensure subject and optionally set schema
    subjectKey := cfg.Producer.SubjectKey
    if subjectKey == "" { subjectKey = "DEMO-1" }
    subjReq := map[string]any{"subject_key": subjectKey, "attrs": map[string]any{"region":"eu"}}
    subjB, _ := json.Marshal(subjReq)
    _, _ = rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"subject:register", Values: map[string]any{"payload": string(subjB), "token": token}}).Result()
    subjMsg, e := xreadOne(ctx, rdb, cfg.Redis.KeyPrefix+"subject:resp:"+producerID, 15*time.Second)
    if e != nil { log.Fatalf("subject_resp_timeout: %v", e) }
    var subjectID string
    if v, ok := subjMsg.Values["subject_id"].(string); ok { subjectID = v }
    if subjectID == "" { log.Fatalf("subject_id_empty") }
    log.Printf("subject_provisioned subject_id=%s", subjectID)

    // periodically send demo events with token
    interval := time.Duration(cfg.Producer.SendIntervalMs) * time.Millisecond
    if interval <= 0 { interval = time.Second }
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    eventsSent := 0
    for {
        select {
        case t := <-ticker.C:
            // lean event payload
            ev := map[string]any{"event_id": t.Format("20060102150405.000000000"), "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": subjectID, "payload": map[string]any{"kind":"status","source": cfg.Producer.Name, "symbol":"DEMO"}}
            evB, _ := json.Marshal(ev)
            id, err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"events", Values: map[string]any{"id": ev["event_id"], "payload": string(evB), "token": token}}).Result()
            if err != nil { 
                log.Printf("event_xadd_error: %v", err) 
            } else { 
                eventsSent++
                if eventsSent == 1 {
                    log.Printf("event_sending_started events_total=1 id=%s", id)
                } else if eventsSent % 100 == 0 {
                    log.Printf("event_sent_progress events_total=%d id=%s", eventsSent, id)
                }
            }
        case <-ctx.Done():
            log.Printf("producer_stop")
            // send deregister on shutdown
            if nonce, e := randNonce(); e == nil {
                if sig, e2 := signPayloadNonce(signer, canonicalJSON(map[string]any{"action":"deregister"}), nonce); e2 == nil {
                    _, _ = rdb.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"register", Values: map[string]any{"action":"deregister", "pubkey": pubForRegistration, "payload": canonicalJSON(map[string]any{"reason":"shutdown"}), "nonce": nonce, "sig": sig}}).Result()
                    // optionally wait brief confirm
                    _, _ = xreadOne(context.Background(), rdb, cfg.Redis.KeyPrefix+"register:resp:"+nonce, 3*time.Second)
                }
            }
            return
        }
    }
}


