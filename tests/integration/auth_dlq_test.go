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
    // deps
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    // Wait for Postgres to be ready before starting kernel
    itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

    // config with auth enabled and require_token
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfig(dsn),
        Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{
            RequireToken: true,
            Issuer: "it",
            Audience: "it",
            KeyID: "k",
            ProducerSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
            AdminSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
        },
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    // wait ready
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    rcli := redis.NewClient(&redis.Options{Addr: addr})
    // publish without token (lean protocol)
    payload := `{"event_id":"01NOAUTH","ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","subject_id":"00000000-0000-0000-0000-000000000000","payload":{"source":"t","symbol":"X"}}`
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id":"01NOAUTH","payload": payload}}).Err(); err != nil {
        t.Fatalf("xadd: %v", err)
    }
    // expect DLQ entry
    waitFor[int64](t, 10*time.Second, func() (int64, bool) {
        l, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
        return l, l >= 1
    })
}


