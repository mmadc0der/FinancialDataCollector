package main

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    ssh "golang.org/x/crypto/ssh"
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
        RegStream  string `yaml:"register_stream"`
        EvStream   string `yaml:"events_stream"`
        RegRespStream string `yaml:"register_resp_stream"`
        CtrlRespStream string `yaml:"control_resp_stream"`
    } `yaml:"redis"`
    Producer struct {
        Name          string `yaml:"name"`
        Contact       string `yaml:"contact"`
        SendIntervalMs int   `yaml:"send_interval_ms"`
        SSHPrivateKeyFile string `yaml:"ssh_private_key_file"`
        SSHPublicKeyFile  string `yaml:"ssh_public_key_file"`
        SSHCertFile       string `yaml:"ssh_cert_file"`
        SchemaName        string `yaml:"schema_name"`
        SchemaVersion     int    `yaml:"schema_version"`
        SubjectKey        string `yaml:"subject_key"`
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
    sum := sha256.Sum256([]byte(pubLine))
    return base64.StdEncoding.EncodeToString(sum[:])
}

func readTrim(path string) (string, error) {
    b, err := os.ReadFile(path)
    if err != nil { return "", err }
    return strings.TrimSpace(string(b)), nil
}

func loadEd25519FromKeyFile(path string) (ed25519.PrivateKey, error) {
    b, err := os.ReadFile(path)
    if err != nil { return nil, err }
    v, err := ssh.ParseRawPrivateKey(b)
    if err != nil {
        // Support passphrase-protected OpenSSH keys via env var
        if passFile := os.Getenv("PRODUCER_SSH_PASSPHRASE_FILE"); passFile != "" {
            if pass, e := os.ReadFile(passFile); e == nil {
                if vv, ee := ssh.ParseRawPrivateKeyWithPassphrase(b, bytes.TrimSpace(pass)); ee == nil {
                    v = vv
                    err = nil
                }
            }
        }
        if err != nil { return nil, err }
    }
    if sk, ok := v.(ed25519.PrivateKey); ok {
        return sk, nil
    }
    return nil, fmt.Errorf("unsupported private key type (need ed25519)")
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
    log.Printf("producer_start addr=%s reg_stream=%s ev_stream=%s prefix=%s interval_ms=%d",
        cfg.Redis.Addr, cfg.Redis.RegStream, cfg.Redis.EvStream, cfg.Redis.KeyPrefix, cfg.Producer.SendIntervalMs)

    // Load keys (prefer files), else generate ephemeral for demo
    var priv ed25519.PrivateKey
    var signer ssh.Signer
    var opensshPub string
    if cfg.Producer.SSHPublicKeyFile != "" {
        if line, err := readTrim(cfg.Producer.SSHPublicKeyFile); err == nil { opensshPub = line } else { log.Fatalf("read_public_key: %v", err) }
    }
    if cfg.Producer.SSHPrivateKeyFile != "" {
        // Load raw ed25519 key for signing (kernel expects ed25519 signature)
        sk, err := loadEd25519FromKeyFile(cfg.Producer.SSHPrivateKeyFile)
        if err != nil { log.Fatalf("read_private_key_ed25519: %v", err) }
        priv = sk
    }
    if len(priv) == 0 || opensshPub == "" {
        // fallback: generate ephemeral
        pub, sk, err := ed25519.GenerateKey(rand.Reader)
        if err != nil { log.Fatal(err) }
        priv = sk
        opensshPub = "ssh-ed25519 " + base64.StdEncoding.EncodeToString(pub)
    }
    // If certificate provided, send cert line as pubkey in registration (server unwraps)
    pubForRegistration := opensshPub
    if cfg.Producer.SSHCertFile != "" {
        if certLine, err := readTrim(cfg.Producer.SSHCertFile); err == nil { pubForRegistration = certLine } else { log.Fatalf("read_cert_file: %v", err) }
    }
    fp := computeFingerprint(pubForRegistration)

    // send registration (repeat later until token received)
    payload := map[string]any{"producer_hint": cfg.Producer.Name, "contact": cfg.Producer.Contact, "meta": map[string]string{"demo":"true"}}
    payloadStr := canonicalJSON(payload)
    nonce := time.Now().Format(time.RFC3339Nano)
    msg := []byte(payloadStr + "." + nonce)
    // Always sign with ed25519 raw signature
    if len(priv) == 0 { log.Fatalf("missing ed25519 private key for signing") }
    sigRaw := ed25519.Sign(priv, msg)
    sigB64 := base64.StdEncoding.EncodeToString(sigRaw)
    regID, err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+cfg.Redis.RegStream, Values: map[string]any{"pubkey": pubForRegistration, "payload": payloadStr, "nonce": nonce, "sig": sigB64}}).Result()
    if err != nil { log.Fatalf("register_xadd_error: %v", err) }
    log.Printf("register_sent id=%s", regID)

    // Wait for token on register response stream (using a dedicated consumer group)
    regResp := cfg.Redis.RegRespStream
    if regResp == "" { regResp = "register:resp" }
    regRespKey := cfg.Redis.KeyPrefix + regResp
    regGroup := "prod-reg-" + fp[:8]
    regConsumer := regGroup + "-1"
    _ = rdb.XGroupCreateMkStream(ctx, regRespKey, regGroup, "$" ).Err()
    var token string
    var producerID string
    reRegTicker := time.NewTicker(30 * time.Second)
    defer reRegTicker.Stop()
TokenWait:
    for token == "" {
        // block read for new entries
        res, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{Group: regGroup, Consumer: regConsumer, Streams: []string{regRespKey, ">"}, Count: 10, Block: 5 * time.Second}).Result()
        if err != nil && err != redis.Nil { time.Sleep(200 * time.Millisecond) }
        for _, s := range res {
            for _, m := range s.Messages {
                if f, _ := m.Values["fingerprint"].(string); f != "" {
                    if f == fp {
                        if t, ok := m.Values["token"].(string); ok && t != "" { token = t }
                        if pid, ok := m.Values["producer_id"].(string); ok { producerID = pid }
                    }
                }
                // ack regardless to avoid backlog
                _ = rdb.XAck(ctx, regRespKey, regGroup, m.ID).Err()
                if token != "" { break TokenWait }
            }
        }
        select {
        case <-reRegTicker.C:
            // re-send registration to trigger token publish if approved while waiting
            nonce = time.Now().Format(time.RFC3339Nano)
            msg = []byte(payloadStr + "." + nonce)
            if signer != nil {
                if sshSig, e := signer.Sign(rand.Reader, msg); e == nil { sigRaw = sshSig.Blob } else { continue }
            } else {
                sigRaw = ed25519.Sign(priv, msg)
            }
            sigB64 = base64.StdEncoding.EncodeToString(sigRaw)
            if id, e := rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+cfg.Redis.RegStream, Values: map[string]any{"pubkey": pubForRegistration, "payload": payloadStr, "nonce": nonce, "sig": sigB64}}).Result(); e == nil {
                log.Printf("register_retry id=%s", id)
            }
        default:
        }
    }
    log.Printf("token_acquired producer_id=%s", producerID)

    // request schema+subject provisioning via control message
    schemaName := cfg.Producer.SchemaName
    if schemaName == "" { schemaName = "demo_schema" }
    schemaVersion := cfg.Producer.SchemaVersion
    if schemaVersion <= 0 { schemaVersion = 1 }
    subjectKey := cfg.Producer.SubjectKey
    if subjectKey == "" { subjectKey = "DEMO-1" }
    ctrl := map[string]any{"version":"0.1.0","type":"control","id":"CTRL1","ts": time.Now().UnixNano(), "data": map[string]any{"op":"ensure_schema_subject","name":schemaName,"version":schemaVersion,"body": map[string]any{"fields": []string{"a", "b"}}, "subject_key":subjectKey,"attrs": map[string]any{"region":"eu"}}}
    ctrlB, _ := json.Marshal(ctrl)
    _, _ = rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+cfg.Redis.EvStream, Values: map[string]any{"id":"CTRL1","payload": string(ctrlB), "token": token}}).Result()

    // Wait for control response with schema_id and subject_id
    ctrlResp := cfg.Redis.CtrlRespStream
    if ctrlResp == "" { ctrlResp = "control:resp" }
    ctrlRespKey := cfg.Redis.KeyPrefix + ctrlResp
    ctrlGroup := "prod-ctl-" + fp[:8]
    ctrlConsumer := ctrlGroup + "-1"
    _ = rdb.XGroupCreateMkStream(ctx, ctrlRespKey, ctrlGroup, "$" ).Err()
    var schemaID, subjectID string
CtrlWait:
    for schemaID == "" || subjectID == "" {
        res, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{Group: ctrlGroup, Consumer: ctrlConsumer, Streams: []string{ctrlRespKey, ">"}, Count: 10, Block: 5 * time.Second}).Result()
        if err != nil && err != redis.Nil { time.Sleep(200 * time.Millisecond) }
        for _, s := range res {
            for _, m := range s.Messages {
                if p, ok := m.Values["payload"].(string); ok && p != "" {
                    var resp struct{ Op string `json:"op"`; SchemaID string `json:"schema_id"`; SubjectID string `json:"subject_id"` }
                    if json.Unmarshal([]byte(p), &resp) == nil && resp.Op == "ensure_schema_subject" {
                        schemaID = resp.SchemaID
                        subjectID = resp.SubjectID
                    }
                }
                _ = rdb.XAck(ctx, ctrlRespKey, ctrlGroup, m.ID).Err()
                if schemaID != "" && subjectID != "" { break CtrlWait }
            }
        }
    }
    log.Printf("provisioned schema_id=%s subject_id=%s", schemaID, subjectID)

    // periodically send demo events with token
    interval := time.Duration(cfg.Producer.SendIntervalMs) * time.Millisecond
    if interval <= 0 { interval = time.Second }
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    for {
        select {
        case t := <-ticker.C:
            env := map[string]any{"version":"0.1.0","type":"data","id": t.Format("20060102150405.000000000"), "ts": time.Now().UnixNano(), "data": map[string]any{"kind":"status","source": cfg.Producer.Name, "symbol":"DEMO", "subject_id": subjectID}}
            envB, _ := json.Marshal(env)
            id, err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+cfg.Redis.EvStream, Values: map[string]any{"id": env["id"], "payload": string(envB), "token": token}}).Result()
            if err != nil { log.Printf("event_xadd_error: %v", err) } else { log.Printf("event_sent id=%s", id) }
        case <-ctx.Done():
            log.Printf("producer_stop")
            return
        }
    }
}


