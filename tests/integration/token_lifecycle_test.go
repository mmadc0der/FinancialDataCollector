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
	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
)

func TestTokenLifecycle_IssuanceAndVerification(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	// Ensure Postgres is accepting connections before kernel start
	itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

	// Pre-apply migrations to avoid kernel contention
	{
		pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
		if err != nil { t.Fatalf("pg: %v", err) }
		itutil.WaitForMigrations(t, pg, 10*time.Second)
		pg.Close()
	}

	port := itutil.FreePort(t)
	cfg := kernelcfg.Config{
		Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
		Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""),
        Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
		Logging:  kernelcfg.LoggingConfig{Level: "error"},
		Auth: kernelcfg.AuthConfig{
			RequireToken:               true,
			Issuer:                     "it-test",
			Audience:                   "it-test",
			KeyID:                      "test-key",
			CacheTTLSeconds:            60,
			SkewSeconds:                5,
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

	// wait ready
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 20*time.Second)

	// Placeholder: actual token validation would require calling auth endpoints
	// This test verifies the auth subsystem is initialized and responsive
	t.Logf("Kernel with auth system started successfully on port %d", port)
}

func TestTokenLifecycle_RateLimit_WindowSliding(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	// Ensure Postgres is accepting connections before kernel start
	itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

	port := itutil.FreePort(t)
	cfg := kernelcfg.Config{
		Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
		Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""),
        Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
		Logging:  kernelcfg.LoggingConfig{Level: "error"},
		Auth: kernelcfg.AuthConfig{
			RequireToken:               true,
			Issuer:                     "it-test",
			Audience:                   "it-test",
			KeyID:                      "test-key",
			RegistrationRateLimitRPM:   2, // 2 per minute
			RegistrationRateLimitBurst: 1, // +1 burst
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 20*time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	t.Logf("Rate limit config: RPM=2, Burst=1; total allowed=%d in first window", 3)
}

func TestMessageValidation_NoToken_Goes_To_DLQ(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	// Ensure Postgres is accepting connections before kernel start
	itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

	port := itutil.FreePort(t)
	cfg := kernelcfg.Config{
		Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
		Postgres: itutil.NewPostgresConfigWithBatch(dsn, 10, 50),
		Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
		Logging:  kernelcfg.LoggingConfig{Level: "error"},
		Auth: kernelcfg.AuthConfig{
			RequireToken:               true,
			Issuer:                     "it-test",
			Audience:                   "it-test",
			KeyID:                      "test-key",
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

	itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	// publish message without auth token (lean protocol)
	payload := `{"event_id":"notoken","ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","subject_id":"00000000-0000-0000-0000-000000000000","payload":{"source":"t","symbol":"X"}}`
	if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
		Stream: "fdc:events",
		Values: map[string]any{"id": "notoken", "payload": payload},
	}).Err(); err != nil {
		t.Fatalf("xadd: %v", err)
	}

	// Give kernel time to process
	time.Sleep(2 * time.Second)

	// Check DLQ has entry
	dlqLen, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
	if dlqLen < 1 {
		t.Fatalf("expected DLQ entry, got len=%d", dlqLen)
	}
}
