//go:build integration

package itutil

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "path/filepath"
    "os"
    "testing"
    "time"

    redismod "github.com/testcontainers/testcontainers-go/modules/redis"
    psqlmod "github.com/testcontainers/testcontainers-go/modules/postgres"

    "github.com/redis/go-redis/v9"
    "github.com/jackc/pgx/v5/pgxpool"

    "github.com/example/data-kernel/internal/kernel"
    "github.com/example/data-kernel/internal/kernelcfg"
    yaml "gopkg.in/yaml.v3"
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
    // Write YAML to ensure tag alignment with kernelcfg.Load
    b, _ := yaml.Marshal(cfg)
    p := filepath.Join(t.TempDir(), "kernel.json")
    if err := os.WriteFile(p, b, 0o644); err != nil { t.Fatalf("write cfg: %v", err) }
    return p
}

// ChdirRepoRoot changes the working directory to the repository root (where go.mod is located).
// This ensures relative paths like "migrations/*.sql" resolve correctly during integration tests.
func ChdirRepoRoot(t *testing.T) {
    t.Helper()
    cwd, _ := os.Getwd()
    dir := cwd
    for i := 0; i < 10; i++ {
        if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
            if chErr := os.Chdir(dir); chErr != nil { t.Fatalf("chdir repo root: %v", chErr) }
            return
        }
        parent := filepath.Dir(dir)
        if parent == dir { break }
        dir = parent
    }
    t.Fatalf("could not find go.mod from %s", cwd)
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

// WaitPostgresReady attempts to connect to Postgres and run a trivial query until success.
func WaitPostgresReady(t *testing.T, dsn string, deadline time.Duration) {
    t.Helper()
    end := time.Now().Add(deadline)
    for time.Now().Before(end) {
        pool, err := pgxpool.New(context.Background(), dsn)
        if err == nil {
            ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
            var one int
            e := pool.QueryRow(ctx, "SELECT 1").Scan(&one)
            cancel()
            pool.Close()
            if e == nil && one == 1 {
                return
            }
        }
        time.Sleep(150 * time.Millisecond)
    }
    t.Fatalf("postgres not ready: %s", dsn)
}


