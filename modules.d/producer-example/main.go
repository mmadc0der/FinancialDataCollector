package main

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "log"
    "os"
    "time"

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
    } `yaml:"redis"`
    Producer struct {
        Name          string `yaml:"name"`
        Contact       string `yaml:"contact"`
        SendIntervalMs int   `yaml:"send_interval_ms"`
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

func main() {
    cfg := loadConfig("modules.d/producer-example/config.yaml")
    ctx := context.Background()
    rdb := redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB})

    // generate ephemeral keypair for demo
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { log.Fatal(err) }
    opensshPub := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(pub)

    // send registration
    payload := map[string]any{"producer_hint": cfg.Producer.Name, "contact": cfg.Producer.Contact, "meta": map[string]string{"demo":"true"}}
    payloadStr := canonicalJSON(payload)
    nonce := time.Now().Format(time.RFC3339Nano)
    msg := []byte(payloadStr + "." + nonce)
    sig := ed25519.Sign(priv, msg)
    sigB64 := base64.StdEncoding.EncodeToString(sig)
    _, err = rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+cfg.Redis.RegStream, Values: map[string]any{"pubkey": opensshPub, "payload": payloadStr, "nonce": nonce, "sig": sigB64}}).Result()
    if err != nil { log.Fatal(err) }

    // request schema+subject provisioning via control message
    ctrl := map[string]any{"version":"0.1.0","type":"control","id":"CTRL1","ts": time.Now().UnixNano(), "data": map[string]any{"op":"ensure_schema_subject","name":"demo_schema","version":1,"body": map[string]any{"fields":["a","b"]}, "subject_key":"DEMO-1","attrs": map[string]any{"region":"eu"}}}
    ctrlB, _ := json.Marshal(ctrl)
    _, _ = rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+cfg.Redis.EvStream, Values: map[string]any{"id":"CTRL1","payload": string(ctrlB)}}).Result()

    // periodically send demo events (without token for simplicity)
    interval := time.Duration(cfg.Producer.SendIntervalMs) * time.Millisecond
    if interval <= 0 { interval = time.Second }
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    for t := range ticker.C {
        env := map[string]any{"version":"0.1.0","type":"data","id": t.Format("20060102150405.000000000"), "ts": time.Now().UnixNano(), "data": map[string]any{"kind":"status","source": cfg.Producer.Name, "symbol":"DEMO"}}
        envB, _ := json.Marshal(env)
        _, _ = rdb.XAdd(ctx, &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+cfg.Redis.EvStream, Values: map[string]any{"id": env["id"], "payload": string(envB)}}).Result()
    }
}


