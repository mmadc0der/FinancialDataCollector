//go:build integration && producer

package producerit

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "testing"
    "time"

    "golang.org/x/crypto/sha3"

    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func hasBinary(name string) bool { _, err := exec.LookPath(name); return err == nil }

func TestProducerExample_EndToEnd(t *testing.T) {
    if os.Getenv("RUN_IT") == "" || os.Getenv("RUN_PRODUCER") == "" { t.Skip("integration producer; set RUN_IT=1 RUN_PRODUCER=1") }
    if !hasBinary("go") { t.Skip("go tool not found in PATH for subprocess run") }
    if !hasBinary("ssh-keygen") { t.Skip("ssh-keygen not found in PATH; required to create ed25519 key") }

    // deps
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    // Ensure Postgres is accepting connections before migrations
    itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

    // Prepare DB & apply migrations
    pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    itutil.WaitForMigrations(t, pg, 10*time.Second)
    pool := pg.Pool()

    // Kernel issuer keys (for token issuance)
    issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("issuer keygen: %v", err) }

    // Start kernel with auth enabled
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 50, 50, ""),
        Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events"},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{RequireToken: true, Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: base64.RawStdEncoding.EncodeToString(issuerPriv), PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(issuerPub)}},
    }
    cancelKernel := itutil.StartKernel(t, cfg)
    defer cancelKernel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 15*time.Second)

    // Generate producer ed25519 keys using ssh-keygen into temp dir
    dir := t.TempDir()
    keyPath := filepath.Join(dir, "id_ed25519")
    cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath)
    if out, err := cmd.CombinedOutput(); err != nil { t.Fatalf("ssh-keygen: %v output=%s", err, string(out)) }
    pubPath := keyPath + ".pub"
    certPath := filepath.Join(dir, "id_ed25519-cert.pub")
    // For test, reuse public key as "cert" line; kernel does not require cert unless ProducerSSHCA is set
    if b, err := os.ReadFile(pubPath); err == nil { _ = os.WriteFile(certPath, b, 0o644) } else { t.Fatalf("read pub: %v", err) }
    pubLineBytes, err := os.ReadFile(pubPath)
    if err != nil { t.Fatalf("read pub: %v", err) }
    pubLine := string(pubLineBytes)
    fp := func(in []byte) string { s := sha3.Sum512(in); return base64.StdEncoding.EncodeToString(s[:]) }([]byte(pubLine))

    // Create producer and approve key in DB for token exchange
    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'producer-example') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3)
        ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID); err != nil {
        t.Fatalf("upsert key: %v", err)
    }

    // Write producer config yaml
    yml := fmt.Sprintf("redis:\n  addr: %q\n  key_prefix: %q\nproducer:\n  name: %q\n  contact: %q\n  send_interval_ms: %d\n  ssh_private_key_file: %q\n  ssh_public_key_file: %q\n  ssh_cert_file: %q\n  subject_key: %q\n",
        addr, "fdc:", "pe-it", "it", 250, keyPath, pubPath, certPath, "PE-SUBJ-1")
    cfgPath := filepath.Join(dir, "producer.yaml")
    if err := os.WriteFile(cfgPath, []byte(yml), 0o644); err != nil { t.Fatalf("write producer cfg: %v", err) }

    // Run producer as subprocess
    ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
    defer cancel()
    run := exec.CommandContext(ctx, "go", "run", "./modules.d/producer-example", "-config", cfgPath, "-interval_ms", "200")
    // capture logs for debugging on failure
    stdout, _ := run.StdoutPipe(); stderr, _ := run.StderrPipe()
    if err := run.Start(); err != nil { t.Fatalf("start producer: %v", err) }
    // drain logs
    go io.Copy(io.Discard, stdout)
    go io.Copy(io.Discard, stderr)

    // Wait for token issuance and first event persisted
    rcli := redis.NewClient(&redis.Options{Addr: addr})
    // token response stream is per producer id; ensure at least one message
    itutil.WaitStreamLen(t, rcli, cfg.Redis.KeyPrefix + "token:resp:"+producerID, 1, 15*time.Second)

    // Wait for event persisted
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 2*time.Second)
    waitUntil(t, 20*time.Second, func() (bool, error) {
        p, _ := pgxpool.New(context.Background(), dsn)
        defer p.Close()
        var cnt int
        _ = p.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.events`).Scan(&cnt)
        if cnt >= 1 { return true, nil }
        return false, nil
    })

    // stop process gracefully
    _ = run.Process.Signal(os.Interrupt)
    _ = run.Wait()
}

func waitUntil(t *testing.T, d time.Duration, fn func() (bool, error)) {
    t.Helper()
    deadline := time.Now().Add(d)
    for time.Now().Before(deadline) {
        ok, err := fn()
        if err == nil && ok { return }
        if err != nil && !errors.Is(err, context.DeadlineExceeded) { /* ignore and retry */ }
        time.Sleep(150 * time.Millisecond)
    }
    t.Fatalf("deadline exceeded")
}


