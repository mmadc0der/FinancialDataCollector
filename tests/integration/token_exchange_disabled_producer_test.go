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

    ssh "golang.org/x/crypto/ssh"

    "github.com/redis/go-redis/v9"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    itutil "github.com/example/data-kernel/tests/itutil"
)

// Disabled producer should not receive token responses on exchange
func TestTokenExchange_DisabledProducer_NoTokenIssued(t *testing.T) {
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

    // Issuer keys and producer cert
    pubTok, privTok, _ := ed25519.GenerateKey(rand.Reader)
    _, caPriv, _ := ed25519.GenerateKey(rand.Reader)
    caSigner, _ := ssh.NewSignerFromKey(caPriv)
    caPubLine := string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    prodPub, _ := ssh.NewPublicKey(pub)
    cert := &ssh.Certificate{Key: prodPub, Serial: 1, CertType: ssh.UserCert, KeyId: "it", ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
    _ = cert.SignCert(rand.Reader, caSigner)
    pubLine := string(ssh.MarshalAuthorizedKey(cert))

    // Producer with approved key, then disable producer
    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name,disabled_at) VALUES (gen_random_uuid(),'tok-dis',now()) RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    _, _ = pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ('tok-dis-fp',$1,'approved',$2) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id`, pubLine, producerID)

    // Start kernel
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: base64.RawStdEncoding.EncodeToString(privTok), PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pubTok)}, ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
    time.Sleep(300 * time.Millisecond)

    r := redis.NewClient(&redis.Options{Addr: addr})
    respStream := cfg.Redis.KeyPrefix+"token:resp:"+producerID

    // Attempt token exchange using pubkey path
    nonce := "tok-dis-1"
    sig := ed25519.Sign(priv, []byte("{}."+nonce))
    sigB64 := base64.RawStdEncoding.EncodeToString(sig)
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"token:exchange", Values: map[string]any{"pubkey": pubLine, "payload": "{}", "nonce": nonce, "sig": sigB64}}).Err(); err != nil { t.Fatalf("xadd: %v", err) }

    // Ensure no response within 3s
    time.Sleep(3 * time.Second)
    if l, _ := r.XLen(context.Background(), respStream).Result(); l > 0 {
        t.Fatalf("expected no token response for disabled producer; got %d messages", l)
    }
}


