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

    "golang.org/x/crypto/sha3"
    ssh "golang.org/x/crypto/ssh"

    "github.com/redis/go-redis/v9"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    itutil "github.com/example/data-kernel/tests/itutil"
)

// Validates registration rate limiting behavior: second request within window is rate_limited,
// responds on per-nonce stream, and does NOT create audit row or nonce guard for that request.
func TestRegistrationRateLimit_PerFingerprint(t *testing.T) {
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

    // CA and producer certificate
    _, caPriv, _ := ed25519.GenerateKey(rand.Reader)
    caSigner, _ := ssh.NewSignerFromKey(caPriv)
    caPubLine := string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))

    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    prodPub, _ := ssh.NewPublicKey(pub)
    cert := &ssh.Certificate{Key: prodPub, Serial: 1, CertType: ssh.UserCert, KeyId: "it", ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
    if err := cert.SignCert(rand.Reader, caSigner); err != nil { t.Fatalf("sign cert: %v", err) }
    pubLine := string(ssh.MarshalAuthorizedKey(cert))
    fp := func(in []byte) string { h := sha3.Sum512(in); return base64.StdEncoding.EncodeToString(h[:]) }([]byte(pubLine))

    // Start kernel with strict low rate limits: 1 RPM, burst 1
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""),
        Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine, RegistrationRateLimitRPM: 1, RegistrationRateLimitBurst: 1},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
    time.Sleep(300 * time.Millisecond)

    // Ensure registration consumer group is ready on the register stream
    r := redis.NewClient(&redis.Options{Addr: addr})
    regStream := cfg.Redis.KeyPrefix+"register"
    endWait := time.Now().Add(5 * time.Second)
    for time.Now().Before(endWait) {
        groups, _ := r.XInfoGroups(context.Background(), regStream).Result()
        ready := false
        for _, g := range groups { if g.Name == cfg.Redis.ConsumerGroup { ready = true; break } }
        if ready { break }
        time.Sleep(100 * time.Millisecond)
    }

    // Prepare canonical payload
    payload := itutil.CanonicalizeJSON([]byte(`{"producer_hint":"rl","meta":{"t":"1"}}`))

    // Send first registration (will likely result in pending, silent response)
    nonce1 := "rate-1"
    sig1 := ed25519.Sign(priv, append([]byte(string(payload)), []byte("."+nonce1)...) )
    sig1B64 := base64.RawStdEncoding.EncodeToString(sig1)
    values1 := map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce1, "sig": sig1B64}
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: regStream, Values: values1}).Err(); err != nil { t.Fatalf("xadd1: %v", err) }

    // Immediately send second registration (same fingerprint), different nonce → should be rate_limited
    nonce2 := "rate-2"
    sig2 := ed25519.Sign(priv, append([]byte(string(payload)), []byte("."+nonce2)...) )
    sig2B64 := base64.RawStdEncoding.EncodeToString(sig2)
    values2 := map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce2, "sig": sig2B64}
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: regStream, Values: values2}).Err(); err != nil { t.Fatalf("xadd2: %v", err) }

    // Expect response on per-nonce stream for nonce2 with status=rate_limited
    respStream2 := cfg.Redis.KeyPrefix+"register:resp:"+nonce2
    msg := itutil.WaitReadStream(t, r, respStream2, 10*time.Second)
    if st, _ := msg.Values["status"].(string); st != "rate_limited" {
        t.Fatalf("expected status=rate_limited, got %v", msg.Values)
    }

    // No audit row should exist for nonce2 (rate-limited before DB)
    var n2 int
    _ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.producer_registrations WHERE fingerprint=$1 AND nonce=$2`, fp, nonce2).Scan(&n2)
    if n2 != 0 { t.Fatalf("expected no audit row for nonce2; got %d", n2) }

    // No nonce guard should be set for nonce2 (guard happens after rate limit)
    nonceKey2 := cfg.Redis.KeyPrefix+"reg:nonce:"+fp+":"+nonce2
    if ex, _ := r.Exists(context.Background(), nonceKey2).Result(); ex != 0 {
        t.Fatalf("expected no nonce guard for rate-limited request; key=%s exists", nonceKey2)
    }
}


