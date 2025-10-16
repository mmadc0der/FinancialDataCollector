//go:build integration

package it

import (
    "context"
    "os"
    "strconv"
    "testing"
    "time"

    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestDLQOnUnauthenticatedPublish(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    // ensure CWD at repo root so migrations resolve
    itutil.ChdirRepoRoot(t)
    // deps
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    // config with auth enabled and require_token
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: true, BatchSize: 10, BatchMaxWaitMs: 50},
        Redis: kernelcfg.RedisConfig{Enabled: true, Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerEnabled: true, PublishEnabled: false},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "it", Audience: "it", KeyID: "k"},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    // wait ready
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

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


