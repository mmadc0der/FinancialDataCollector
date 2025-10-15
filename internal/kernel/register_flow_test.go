//go:build integration

package kernel

import (
    "context"
    "encoding/json"
    "encoding/base64"
    "os"
    "path/filepath"
    "net/http"
    "testing"
    "time"

    "crypto/ed25519"
    "crypto/rand"
    "golang.org/x/crypto/sha3"

    redismod "github.com/testcontainers/testcontainers-go/modules/redis"
    psqlmod "github.com/testcontainers/testcontainers-go/modules/postgres"

    "github.com/redis/go-redis/v9"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func startPg(t *testing.T) (*psqlmod.PostgresContainer, string) {
    t.Helper()
    ctx := context.Background()
    pg, err := psqlmod.RunContainer(ctx, psqlmod.WithDatabase("testdb"), psqlmod.WithUsername("test"), psqlmod.WithPassword("test"))
    if err != nil { t.Fatalf("pg up: %v", err) }
    dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
    if err != nil { t.Fatalf("pg dsn: %v", err) }
    return pg, dsn
}

func startRd(t *testing.T) (*redismod.RedisContainer, string) {
    t.Helper()
    ctx := context.Background()
    r, err := redismod.RunContainer(ctx)
    if err != nil { t.Fatalf("redis up: %v", err) }
    host, err := r.Host(ctx)
    if err != nil { t.Fatalf("redis host: %v", err) }
    port, err := r.MappedPort(ctx, "6379")
    if err != nil { t.Fatalf("redis port: %v", err) }
    return r, host+":"+port.Port()
}

func TestRegisterAndDeregister_Flow(t *testing.T) {
    if testing.Short() || os.Getenv("RUN_IT") == "" { t.Skip("integration; set RUN_IT=1") }
    pgc, dsn := startPg(t)
    defer pgc.Terminate(context.Background())
    rc, addr := startRd(t)
    defer rc.Terminate(context.Background())

    // start kernel
    cfg := minimalConfig(dsn, addr)
    cfgPath := writeTempKernelConfig(t, cfg)
    k, err := NewKernel(cfgPath)
    if err != nil { t.Fatalf("kernel: %v", err) }
    ctx, cancel := context.WithCancel(context.Background()); defer cancel()
    go func(){ _ = k.Start(ctx) }()

    waitReady(t, ":7600")

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
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:register", Values: map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce, "sig": sigB64}}).Err(); err != nil {
        t.Fatalf("xadd reg: %v", err)
    }
    // wait resp on per-nonce stream
    waitForLen(t, rcli, "fdc:register:resp:"+nonce, 1)

    // deregister
    nonce2 := "8899aabbccddeeff"
    sum2 := sha3.Sum512([]byte("{}." + nonce2))
    sig2 := ed25519.Sign(priv, sum2[:])
    sig2B64 := base64.RawStdEncoding.EncodeToString(sig2)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:register", Values: map[string]any{"action":"deregister", "pubkey": pubLine, "payload": "{}", "nonce": nonce2, "sig": sig2B64}}).Err(); err != nil {
        t.Fatalf("xadd dereg: %v", err)
    }
    waitForLen(t, rcli, "fdc:register:resp:"+nonce2, 1)
}

func writeTempKernelConfig(t *testing.T, cfg any) string {
    t.Helper()
    b, _ := json.Marshal(cfg)
    p := filepath.Join(t.TempDir(), "kernel.json")
    if err := os.WriteFile(p, b, 0o644); err != nil { t.Fatalf("write cfg: %v", err) }
    return p
}

func minimalConfig(dsn, addr string) kernelcfg.Config {
    return kernelcfg.Config{
        Server:   kernelcfg.ServerConfig{Listen: ":7600"},
        Postgres: kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: true, BatchSize: 50, BatchMaxWaitMs: 50},
        Redis:    kernelcfg.RedisConfig{Enabled: true, Addr: addr, KeyPrefix: "fdc:", ConsumerEnabled: true, Stream: "events"},
        Logging:  kernelcfg.LoggingConfig{Level: "error"},
        Auth:     kernelcfg.AuthConfig{Enabled: false},
    }
}

func waitReady(t *testing.T, addr string) {
    t.Helper()
    waitFor[bool](t, 10*time.Second, func() (bool, bool) {
        resp, err := http.Get("http://127.0.0.1"+addr+"/readyz")
        if err != nil { return false, false }
        defer resp.Body.Close()
        return resp.StatusCode == 200, resp.StatusCode == 200
    })
}

func waitForLen(t *testing.T, r *redis.Client, stream string, want int64) {
    t.Helper()
    waitFor[int64](t, 10*time.Second, func() (int64, bool) {
        l, _ := r.XLen(context.Background(), stream).Result()
        return l, l >= want
    })
}


