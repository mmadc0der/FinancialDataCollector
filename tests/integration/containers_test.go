//go:build integration

package it

import (
    "context"
    "fmt"
    "os"
    "testing"
    "time"

    psqlmod "github.com/testcontainers/testcontainers-go/modules/postgres"
    redismod "github.com/testcontainers/testcontainers-go/modules/redis"
)

// TestMain ensures dockerized dependencies are up before integration tests.
func TestMain(m *testing.M) {
    code := m.Run()
    os.Exit(code)
}

func startPostgres(t *testing.T) (*psqlmod.PostgresContainer, string) {
    t.Helper()
    ctx := context.Background()
    pg, err := psqlmod.RunContainer(ctx, psqlmod.WithDatabase("testdb"), psqlmod.WithUsername("test"), psqlmod.WithPassword("test"))
    if err != nil { t.Fatalf("pg up: %v", err) }
    dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
    if err != nil { t.Fatalf("pg dsn: %v", err) }
    return pg, dsn
}

func startRedis(t *testing.T) (*redismod.RedisContainer, string) {
    t.Helper()
    ctx := context.Background()
    r, err := redismod.RunContainer(ctx)
    if err != nil { t.Fatalf("redis up: %v", err) }
    host, err := r.Host(ctx)
    if err != nil { t.Fatalf("redis host: %v", err) }
    port, err := r.MappedPort(ctx, "6379")
    if err != nil { t.Fatalf("redis port: %v", err) }
    addr := fmt.Sprintf("%s:%s", host, port.Port())
    return r, addr
}

func waitFor[T any](t *testing.T, deadline time.Duration, fn func() (T, bool)) T {
    t.Helper()
    end := time.Now().Add(deadline)
    var zero T
    for time.Now().Before(end) {
        if v, ok := fn(); ok { return v }
        time.Sleep(100 * time.Millisecond)
    }
    return zero
}


