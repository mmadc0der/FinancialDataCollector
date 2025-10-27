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

// Token exchange rate limit: with 1 RPM burst 1, second immediate request should be silently dropped (no response)
func TestTokenExchange_RateLimit_SilentDrop(t *testing.T) {
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

    // Prepare approved producer and key; also issuer keys for token verification
    pubTok, privTok, _ := ed25519.GenerateKey(rand.Reader)
    // Exchange path uses producer SSH cert and key status approved, not token
    _, caPriv, _ := ed25519.GenerateKey(rand.Reader)
    caSigner, _ := ssh.NewSignerFromKey(caPriv)
    caPubLine := string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))

    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    prodPub, _ := ssh.NewPublicKey(pub)
    cert := &ssh.Certificate{Key: prodPub, Serial: 1, CertType: ssh.UserCert, KeyId: "it", ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
    if err := cert.SignCert(rand.Reader, caSigner); err != nil { t.Fatalf("sign cert: %v", err) }
    pubLine := string(ssh.MarshalAuthorizedKey(cert))
    // Compute fingerprint same as kernel
    fp := func(in []byte) string { h := sha3.Sum512(in); return base64.StdEncoding.EncodeToString(h[:]) }([]byte(pubLine))

    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'tok-rl') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    // Bind the computed fingerprint as approved
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID); err != nil {
        t.Fatalf("upsert key: %v", err)
    }

    // Start kernel with strict low rate limits for registration/token
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""),
        Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: base64.RawStdEncoding.EncodeToString(privTok), PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pubTok)}, ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine, RegistrationRateLimitRPM: 1, RegistrationRateLimitBurst: 1},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
    time.Sleep(300 * time.Millisecond)

    r := redis.NewClient(&redis.Options{Addr: addr})
    respStream := cfg.Redis.KeyPrefix+"token:resp:"+producerID

    // First exchange request
    nonce1 := "tok-rl-1"
    sig1 := ed25519.Sign(priv, []byte("{}."+nonce1))
    sig1B64 := base64.RawStdEncoding.EncodeToString(sig1)
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"token:exchange", Values: map[string]any{"pubkey": pubLine, "payload": "{}", "nonce": nonce1, "sig": sig1B64}}).Err(); err != nil { t.Fatalf("xadd1: %v", err) }
    // Wait for first token response
    _ = itutil.WaitReadStream(t, r, respStream, 10*time.Second)

    // Second immediate exchange request should be silently rate-limited (no response)
    nonce2 := "tok-rl-2"
    sig2 := ed25519.Sign(priv, []byte("{}."+nonce2))
    sig2B64 := base64.RawStdEncoding.EncodeToString(sig2)
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"token:exchange", Values: map[string]any{"pubkey": pubLine, "payload": "{}", "nonce": nonce2, "sig": sig2B64}}).Err(); err != nil { t.Fatalf("xadd2: %v", err) }
    // Ensure no new messages arrive within 3s
    l0, _ := r.XLen(context.Background(), respStream).Result()
    time.Sleep(3 * time.Second)
    l1, _ := r.XLen(context.Background(), respStream).Result()
    if l1 > l0 { t.Fatalf("expected silent drop with no response; got new messages: before=%d after=%d", l0, l1) }
}


