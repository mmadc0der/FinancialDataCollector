//go:build integration

package kernel

import (
    "context"
    "encoding/base64"
    "strconv"
    "os"
    "testing"
    "time"

    "crypto/ed25519"
    "crypto/rand"
    "golang.org/x/crypto/sha3"

    "github.com/redis/go-redis/v9"
    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestRegisterAndDeregister_Flow(t *testing.T) {
    if testing.Short() || os.Getenv("RUN_IT") == "" { t.Skip("integration; set RUN_IT=1") }
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    // start kernel
    port := itutil.FreePort(t)
    cfg := minimalConfig(dsn, addr)
    cfg.Server.Listen = ":" + fmtInt(port)
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+fmtInt(port)+"/readyz", 10*time.Second)

    // registration request for new key
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("keygen: %v", err) }
    pubLine := "ssh-ed25519 "+base64.StdEncoding.EncodeToString(pub)+" it@unit"
    payload := []byte(`{"producer_hint":"unit","meta":{"t":"1"}}`)
    nonce := "0011223344556677"
    sum := sha3.Sum512(append(append([]byte{}, payload...), append([]byte{'.'}, []byte(nonce)...)...))
    sig := ed25519.Sign(priv, sum[:])
    sigB64 := base64.RawStdEncoding.EncodeToString(sig)

    rcli := redis.NewClient(&redis.Options{Addr: addr})
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix + "register", Values: map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce, "sig": sigB64}}).Err(); err != nil {
        t.Fatalf("xadd reg: %v", err)
    }
    // wait resp on per-nonce stream
    itutil.WaitStreamLen(t, rcli, cfg.Redis.KeyPrefix + "register:resp:"+nonce, 1, 10*time.Second)

    // deregister
    nonce2 := "8899aabbccddeeff"
    sum2 := sha3.Sum512([]byte("{}." + nonce2))
    sig2 := ed25519.Sign(priv, sum2[:])
    sig2B64 := base64.RawStdEncoding.EncodeToString(sig2)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix + "register", Values: map[string]any{"action":"deregister", "pubkey": pubLine, "payload": "{}", "nonce": nonce2, "sig": sig2B64}}).Err(); err != nil {
        t.Fatalf("xadd dereg: %v", err)
    }
    itutil.WaitStreamLen(t, rcli, cfg.Redis.KeyPrefix + "register:resp:"+nonce2, 1, 10*time.Second)
}

func minimalConfig(dsn, addr string) kernelcfg.Config {
    return kernelcfg.Config{
        Server:   kernelcfg.ServerConfig{Listen: ":0"},
        Postgres: kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: true, BatchSize: 50, BatchMaxWaitMs: 50},
        Redis:    kernelcfg.RedisConfig{Enabled: true, Addr: addr, KeyPrefix: "fdc:", ConsumerEnabled: true, Stream: "events"},
        Logging:  kernelcfg.LoggingConfig{Level: "error"},
        Auth:     kernelcfg.AuthConfig{Enabled: false},
    }
}
func fmtInt(n int) string { return strconv.Itoa(n) }
