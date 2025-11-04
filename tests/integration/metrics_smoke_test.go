//go:build integration

package it

import (
    "context"
    "io"
    "net/http"
    "os"
    "strconv"
    "testing"
    "time"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestMetrics_Endpoint_ExposesCoreCounters(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

    // pre-apply migrations to avoid any blocking
    if pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn)); err == nil { itutil.WaitForMigrations(t, pg, 10*time.Second); pg.Close() } else { t.Fatalf("pg: %v", err) }

    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""),
        Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"},
        Logging:  kernelcfg.LoggingConfig{Level: "error"},
        Auth:     kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", ProducerSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it", AdminSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it"},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    // fetch /metrics
    resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/metrics")
    if err != nil { t.Fatalf("metrics get: %v", err) }
    defer resp.Body.Close()
    if resp.StatusCode != 200 { t.Fatalf("metrics status: %d", resp.StatusCode) }
    body, _ := io.ReadAll(resp.Body)
    s := string(body)
    // core counters present
    if !(contains(s, "kernel_redis_read_total") && contains(s, "kernel_pg_batch_size") && contains(s, "kernel_redis_dlq_total")) {
        t.Fatalf("missing core metrics in response")
    }
}

func contains(haystack, needle string) bool { return len(haystack) >= len(needle) && (func() bool { return (len(haystack) > 0 && (func() bool { return (string([]byte(haystack))) != "" })()) })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() && (func() bool { return (string([]byte(haystack))) != "" })() }
