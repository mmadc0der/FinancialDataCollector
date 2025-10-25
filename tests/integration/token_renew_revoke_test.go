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

    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/auth"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestTokenExchange_RenewalWithExistingToken(t *testing.T) {
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

    // create approved producer
    var producerID string
    if err := pg.Pool().QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'t-renew') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }

    port := itutil.FreePort(t)
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: base64.RawStdEncoding.EncodeToString(priv), PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}, ProducerSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it", AdminSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it"}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    // Issue initial token directly (issuer configured)
    ver, _ := auth.NewVerifier(cfg.Auth, pg, nil)
    tok, _, _, _ := ver.Issue(context.Background(), producerID, time.Hour, "renew", "")

    // Ask for renewal with existing token
    r := redis.NewClient(&redis.Options{Addr: addr})
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"token:exchange", Values: map[string]any{"token": tok}}).Err()
    res, _ := r.XRead(context.Background(), &redis.XReadArgs{Streams: []string{cfg.Redis.KeyPrefix+"token:resp:"+producerID, "0-0"}, Count: 1, Block: 5 * time.Second}).Result()
    if len(res) == 0 || len(res[0].Messages) == 0 { t.Fatalf("no renewal response") }
}

func TestTokenRevocation_BlocksVerification(t *testing.T) {
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

    var producerID string
    if err := pg.Pool().QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'t-revoke') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }

    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: base64.RawStdEncoding.EncodeToString(priv), PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}}
    ver, _ := auth.NewVerifier(cfg, pg, nil)
    tok, jti, _, _ := ver.Issue(context.Background(), producerID, time.Hour, "", "")
    // Use Postgres direct revoke to avoid multi-statement error in prepared exec
    if err := pg.RevokeToken(context.Background(), jti, "test"); err != nil { t.Fatalf("revoke: %v", err) }
    if _, _, _, err := ver.Verify(context.Background(), tok); err == nil { t.Fatalf("expected revoked token to fail verify") }
}


