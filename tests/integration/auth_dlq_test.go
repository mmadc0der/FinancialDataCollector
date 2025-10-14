//go:build integration

package it

import (
    "context"
    "encoding/json"
    "net/http"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/redis/go-redis/v9"

    "github.com/example/data-kernel/internal/kernel"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestDLQOnUnauthenticatedPublish(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    // deps
    pgc, dsn := startPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := startRedis(t)
    defer rc.Terminate(context.Background())

    // config with auth enabled and require_token
    dir := t.TempDir()
    cfgPath := filepath.Join(dir, "kernel.yaml")
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":7601"},
        Postgres: kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: true, BatchSize: 10, BatchMaxWaitMs: 50},
        Redis: kernelcfg.RedisConfig{Enabled: true, Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerEnabled: true, PublishEnabled: false},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "it", Audience: "it", KeyID: "k"},
    }
    b, _ := json.Marshal(cfg)
    if err := os.WriteFile(cfgPath, b, 0o644); err != nil { t.Fatalf("write cfg: %v", err) }

    k, err := kernel.NewKernel(cfgPath)
    if err != nil { t.Fatalf("kernel new: %v", err) }
    ctx, cancel := context.WithCancel(context.Background()); defer cancel()
    go func() { _ = k.Start(ctx) }()

    // wait ready
    waitFor[bool](t, 10*time.Second, func() (bool, bool) {
        resp, err := http.Get("http://127.0.0.1:7601/readyz")
        if err != nil { return false, false }
        defer resp.Body.Close()
        return resp.StatusCode == 200, resp.StatusCode == 200
    })

    rcli := redis.NewClient(&redis.Options{Addr: addr})
    // publish without token
    payload := []byte(`{"version":"0.1.0","type":"data","id":"01NOAUTH","ts":1730000000000000000,"data":{"source":"t","symbol":"X"}}`)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id":"01NOAUTH","payload": payload}}).Err(); err != nil {
        t.Fatalf("xadd: %v", err)
    }
    // expect DLQ entry
    waitFor[int64](t, 10*time.Second, func() (int64, bool) {
        l, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
        return l, l >= 1
    })
}


