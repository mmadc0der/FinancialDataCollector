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

	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
	itutil "github.com/example/data-kernel/tests/itutil"
)

func TestSubjectUpgrade_FlowAndInvalidPayload(t *testing.T) {
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

    // Start kernel
    port := itutil.FreePort(t)
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: base64.RawStdEncoding.EncodeToString(priv), PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}, ProducerSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it", AdminSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it"}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    r := redis.NewClient(&redis.Options{Addr: addr})

    // Register: op=register
    reg := itutil.CanonicalizeJSON([]byte(`{"op":"register","subject_key":"UP-1","schema_name":"sf","schema_body":{"a":1}}`))
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:subject:register", Values: map[string]any{"payload": string(reg)}}).Err()
    time.Sleep(500 * time.Millisecond)

    // Upgrade: op=upgrade with delta
    up := itutil.CanonicalizeJSON([]byte(`{"op":"upgrade","subject_key":"UP-1","schema_name":"sf","schema_delta":{"b":2}}`))
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:subject:register", Values: map[string]any{"payload": string(up)}}).Err()

    // Invalid: body present for upgrade -> should be ignored/denied (no panic)
    bad := itutil.CanonicalizeJSON([]byte(`{"op":"upgrade","subject_key":"UP-1","schema_name":"sf","schema_body":{"x":3}}`))
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:subject:register", Values: map[string]any{"payload": string(bad)}}).Err()
}


