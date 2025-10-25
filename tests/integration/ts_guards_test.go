//go:build integration

package it

import (
    "context"
    "encoding/base64"
    "os"
    "strconv"
    "testing"
    "time"

    "crypto/ed25519"
    "crypto/rand"
    "encoding/json"

    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestTimestampGuards_RejectedToDLQ(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

    // Pre-apply migrations
    if pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn)); err == nil { itutil.WaitForMigrations(t, pg, 10*time.Second); pg.Close() } else { t.Fatalf("pg: %v", err) }

    // Kernel
    port := itutil.FreePort(t)
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.Config{
        Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 100, ""),
        Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
        Logging:  kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{
            Issuer:   "it",
            Audience: "it",
            KeyID:    "k",
            PrivateKey: base64.RawStdEncoding.EncodeToString(priv),
            PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)},
            ProducerSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
            AdminSSHCA:    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
        },
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    rcli := redis.NewClient(&redis.Options{Addr: addr})

    // Use a fake subject_id/producer token not required since guards happen before insert and we test DLQ path without token
    // Past older than 1 month
    past := time.Now().AddDate(0, -2, 0).UTC().Format(time.RFC3339Nano)
    p := map[string]any{"event_id": "guard-past", "ts": past, "subject_id": "00000000-0000-0000-0000-000000000000", "payload": map[string]any{"k":"v"}}
    pb, _ := json.Marshal(p)
    _ = rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": "guard-past", "payload": string(pb)}}).Err()

    // Future > +1h
    future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339Nano)
    f := map[string]any{"event_id": "guard-future", "ts": future, "subject_id": "00000000-0000-0000-0000-000000000000", "payload": map[string]any{"k":"v"}}
    fb, _ := json.Marshal(f)
    _ = rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": "guard-future", "payload": string(fb)}}).Err()

    // Expect DLQ entries present
    itutil.WaitStreamLen(t, rcli, "fdc:events:dlq", 2, 10*time.Second)
}


