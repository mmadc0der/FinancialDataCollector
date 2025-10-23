//go:build integration

package itutil

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "testing"
    "time"

    redismod "github.com/testcontainers/testcontainers-go/modules/redis"
    psqlmod "github.com/testcontainers/testcontainers-go/modules/postgres"
    "gopkg.in/yaml.v3"

    "github.com/redis/go-redis/v9"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernel"
    "github.com/example/data-kernel/internal/kernelcfg"
)

// StartPostgres launches a Postgres container and returns the container handle and DSN.
func StartPostgres(t *testing.T) (*psqlmod.PostgresContainer, string) {
    t.Helper()
    ctx := context.Background()
    pg, err := psqlmod.RunContainer(ctx, psqlmod.WithDatabase("testdb"), psqlmod.WithUsername("test"), psqlmod.WithPassword("test"))
    if err != nil { t.Fatalf("pg up: %v", err) }
    dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
    if err != nil { t.Fatalf("pg dsn: %v", err) }
    return pg, dsn
}

// StartRedis launches a Redis container and returns the container handle and address.
func StartRedis(t *testing.T) (*redismod.RedisContainer, string) {
    t.Helper()
    ctx := context.Background()
    r, err := redismod.RunContainer(ctx)
    if err != nil { t.Fatalf("redis up: %v", err) }
    host, err := r.Host(ctx)
    if err != nil { t.Fatalf("redis host: %v", err) }
    port, err := r.MappedPort(ctx, "6379")
    if err != nil { t.Fatalf("redis port: %v", err) }
    return r, fmt.Sprintf("%s:%s", host, port.Port())
}

// FreePort finds a free TCP port on localhost.
func FreePort(t *testing.T) int {
    t.Helper()
    l, err := net.Listen("tcp", ":0")
    if err != nil { t.Fatalf("listen :0: %v", err) }
    defer l.Close()
    return l.Addr().(*net.TCPAddr).Port
}

// WriteKernelConfig writes a kernel config to a temp file and returns its path.
func WriteKernelConfig(t *testing.T, cfg kernelcfg.Config) string {
    t.Helper()
    b, _ := yaml.Marshal(cfg)
    p := filepath.Join(t.TempDir(), "kernel.yaml")
    if err := os.WriteFile(p, b, 0o644); err != nil { t.Fatalf("write cfg: %v", err) }
    return p
}

// StartKernel starts the kernel with the provided config and returns a cancel function.
func StartKernel(t *testing.T, cfg kernelcfg.Config) func() {
    t.Helper()
    cfgPath := WriteKernelConfig(t, cfg)
    k, err := kernel.NewKernel(cfgPath)
    if err != nil { t.Fatalf("kernel new: %v", err) }
    ctx, cancel := context.WithCancel(context.Background())
    go func() { _ = k.Start(ctx) }()
    return cancel
}

// WaitHTTPReady polls the given URL until it returns 200 or times out.
func WaitHTTPReady(t *testing.T, url string, deadline time.Duration) {
    t.Helper()
    end := time.Now().Add(deadline)
    for time.Now().Before(end) {
        resp, err := http.Get(url)
        if err == nil {
            if resp.StatusCode == 200 { resp.Body.Close(); return }
            resp.Body.Close()
        }
        time.Sleep(100 * time.Millisecond)
    }
    t.Fatalf("ready timeout for %s", url)
}

// WaitStreamLen waits until the stream has at least want entries.
func WaitStreamLen(t *testing.T, r *redis.Client, stream string, want int64, deadline time.Duration) {
    t.Helper()
    end := time.Now().Add(deadline)
    for time.Now().Before(end) {
        l, _ := r.XLen(context.Background(), stream).Result()
        if l >= want { return }
        time.Sleep(100 * time.Millisecond)
    }
    t.Fatalf("stream %s did not reach len %d", stream, want)
}

// WaitReadStream reads one message from a stream starting from 0-0 within the deadline.
func WaitReadStream(t *testing.T, r *redis.Client, stream string, deadline time.Duration) redis.XMessage {
    t.Helper()
    end := time.Now().Add(deadline)
    for time.Now().Before(end) {
        res, _ := r.XRead(context.Background(), &redis.XReadArgs{Streams: []string{stream, "0-0"}, Count: 1, Block: 2 * time.Second}).Result()
        if len(res) > 0 && len(res[0].Messages) > 0 { return res[0].Messages[0] }
        time.Sleep(50 * time.Millisecond)
    }
    t.Fatalf("timeout reading from stream %s", stream)
    return redis.XMessage{}
}

// NewPostgresConfig creates a PostgresConfig with the correct migrations directory for integration tests
func NewPostgresConfig(dsn string) kernelcfg.PostgresConfig {
	return kernelcfg.PostgresConfig{
		DSN:             dsn,
		ApplyMigrations: true,
		MigrationsDir:   "../../migrations", // Point to project root migrations
		BatchSize:       10,
		BatchMaxWaitMs:  50,
	}
}

// NewPostgresConfigWithBatch creates a PostgresConfig with custom batch settings
func NewPostgresConfigWithBatch(dsn string, batchSize int, batchWaitMs int) kernelcfg.PostgresConfig {
	return kernelcfg.PostgresConfig{
		DSN:             dsn,
		ApplyMigrations: true,
		MigrationsDir:   "../../migrations", // Point to project root migrations
		BatchSize:       batchSize,
		BatchMaxWaitMs:  batchWaitMs,
	}
}

// NewPostgresConfigNoMigrations creates a PostgresConfig without applying migrations but with correct directory
func NewPostgresConfigNoMigrations(dsn string, batchSize int, batchWaitMs int, defaultProducerID string) kernelcfg.PostgresConfig {
	return kernelcfg.PostgresConfig{
		DSN:               dsn,
		ApplyMigrations:   false,
		MigrationsDir:     "../../migrations", // Point to project root migrations
		BatchSize:         batchSize,
		BatchMaxWaitMs:    batchWaitMs,
		DefaultProducerID: defaultProducerID,
	}
}

// WaitForMigrations waits for database migrations to complete by checking for required tables
func WaitForMigrations(t *testing.T, pg *data.Postgres, deadline time.Duration) {
    t.Helper()
    end := time.Now().Add(deadline)
    for time.Now().Before(end) {
        // Check if core tables exist
        var exists bool
        err := pg.Pool().QueryRow(context.Background(), 
            `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'schemas')`).Scan(&exists)
        if err == nil && exists {
            return
        }
        time.Sleep(100 * time.Millisecond)
    }
    t.Fatalf("migrations did not complete within %v", deadline)
}


