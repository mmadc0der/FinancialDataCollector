//go:build integration

package it

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "os"
    "strconv"
    "testing"
    "time"

    "crypto/ed25519"
    "crypto/rand"

    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/auth"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestProducerDisable_DeniesIngestAndExchange(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    itutil.WaitForPostgresReady(t, dsn, 10*time.Second)
    pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    itutil.WaitForMigrations(t, pg, 10*time.Second)
    pool := pg.Pool()

    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'pd') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }

    port := itutil.FreePort(t)
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: base64.RawStdEncoding.EncodeToString(priv), PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}, ProducerSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it", AdminSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it"}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    ver, _ := auth.NewVerifier(cfg.Auth, pg, nil)
    tok, _, _, _ := ver.Issue(context.Background(), producerID, time.Hour, "", "")

    // disable producer
    if err := pg.DisableProducer(context.Background(), producerID); err != nil { t.Fatalf("disable: %v", err) }

    // publish event => DLQ
    r := redis.NewClient(&redis.Options{Addr: addr})
    ev := map[string]any{"event_id": "pd-1", "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": "00000000-0000-0000-0000-000000000000", "payload": map[string]any{"k":"v"}}
    b, _ := json.Marshal(ev)
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": "pd-1", "payload": string(b), "token": tok}}).Err()
    itutil.WaitStreamLen(t, r, "fdc:events:dlq", 1, 10*time.Second)

    // token exchange denied
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"token:exchange", Values: map[string]any{"token": tok}}).Err()
    time.Sleep(500 * time.Millisecond)
    l, _ := r.XLen(context.Background(), cfg.Redis.KeyPrefix+"token:resp:"+producerID).Result()
    if l > 0 { t.Fatalf("expected no token renewal for disabled producer") }
}


