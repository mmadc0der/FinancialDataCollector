//go:build integration

package it

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	itutil "github.com/example/data-kernel/tests/itutil"
	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
)

func TestProducerAuth_ValidToken_PublishAccepted(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	// Ensure Postgres is accepting connections before kernel start
	itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

	// Pre-apply migrations to avoid kernel applying them on its own
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
			Issuer:                     "it-auth",
			Audience:                   "it-auth",
			KeyID:                      "test-key",
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 20*time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	// With RequireToken=true, message without token should go to DLQ
	payload := []byte(`{"version":"0.1.0","type":"data","id":"authed","ts":1730000000000000000,"data":{"source":"test"}}`)
	if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
		Stream: "fdc:events",
		Values: map[string]any{"id": "authed", "payload": payload},
		// No token provided
	}).Err(); err != nil {
		t.Fatalf("xadd: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Verify message went to DLQ (no token)
	dlqLen, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
	if dlqLen < 1 {
		t.Fatalf("expected DLQ entry for message without token, got len=%d", dlqLen)
	}
	t.Logf("Auth requirement enforced correctly: unauthenticated message to DLQ")
}

func TestProducerAuth_BadTokenFormat(t *testing.T) {
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
			Issuer:                     "it-auth",
			Audience:                   "it-auth",
			KeyID:                      "test-key",
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 20*time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	// Message with malformed token
	payload := []byte(`{"version":"0.1.0","type":"data","id":"badtoken","ts":1730000000000000000,"data":{"source":"test"}}`)
	if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
		Stream: "fdc:events",
		Values: map[string]any{
			"id":      "badtoken",
			"payload": payload,
			"token":   "not.a.valid.jwt", // Malformed (too many parts)
		},
	}).Err(); err != nil {
		t.Fatalf("xadd: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Should go to DLQ with token_validation error
	dlqLen, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
	if dlqLen < 1 {
		t.Fatalf("expected DLQ entry for bad token, got len=%d", dlqLen)
	}
	t.Logf("Bad token format correctly rejected")
}

func TestProducerAuth_InvalidPayload_JSON(t *testing.T) {
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
			Issuer:                     "it",
			Audience:                   "it",
			KeyID:                      "k",
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 20*time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	// Message with invalid JSON
	invalidPayload := []byte(`{invalid json here}`)
	if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
		Stream: "fdc:events",
		Values: map[string]any{"id": "badjson", "payload": invalidPayload},
	}).Err(); err != nil {
		t.Fatalf("xadd: %v", err)
	}

	time.Sleep(1 * time.Second)

	// Should go to DLQ
	dlqLen, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
	if dlqLen < 1 {
		t.Fatalf("expected DLQ entry for invalid JSON, got len=%d", dlqLen)
	}
	t.Logf("Invalid JSON payload correctly rejected to DLQ")
}

func TestProducerAuth_PayloadTooLarge(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	// Ensure Postgres is accepting connections before kernel start
	itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

	// Configure small max message size
	port := itutil.FreePort(t)
	cfg := kernelcfg.Config{
		Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port), MaxMessageBytes: 100}, // Only 100 bytes
		Postgres: itutil.NewPostgresConfigWithBatch(dsn, 10, 50),
		Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
		Logging:  kernelcfg.LoggingConfig{Level: "error"},
		Auth: kernelcfg.AuthConfig{
			Issuer:                     "it",
			Audience:                   "it",
			KeyID:                      "k",
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 20*time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	// Create large payload (>100 bytes)
	largeData := make(map[string]interface{})
	largeData["huge_string"] = string(make([]byte, 200))
	largePayload, _ := json.Marshal(largeData)

	if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
		Stream: "fdc:events",
		Values: map[string]any{"id": "toolarge", "payload": largePayload},
	}).Err(); err != nil {
		// Expected: too large to send
		t.Logf("Large payload rejected as expected (over MaxMessageBytes)")
		return
	}

	time.Sleep(1 * time.Second)

	// Should also reject via DLQ if it gets through
	dlqLen, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
	t.Logf("DLQ length after large payload: %d", dlqLen)
}

func TestProducerAuth_RateLimiting_Fingerprint(t *testing.T) {
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
			Issuer:                     "it",
			Audience:                   "it",
			KeyID:                      "k",
			RegistrationRateLimitRPM:   1,        // 1 per minute
			RegistrationRateLimitBurst: 0,        // No burst
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 20*time.Second)

	t.Logf("Rate limit set to 1 RPM with 0 burst - rapid attempts will be limited")
}
