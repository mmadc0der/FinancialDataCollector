//go:build integration

package it

import (
    "context"
    "encoding/base64"
    "encoding/json"
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

// Subject register rate limiting: second immediate request returns error=rate_limited on subject:resp
func TestSubjectRegister_RateLimit_ReturnsError(t *testing.T) {
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
    _ = cert.SignCert(rand.Reader, caSigner)
    pubLine := string(ssh.MarshalAuthorizedKey(cert))

    // Approved producer
    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'subj-rl') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    _, _ = pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ('subj-rl-fp',$1,'approved',$2) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id`, pubLine, producerID)

    // Start kernel with strict rate limit (1 RPM, burst 1)
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine, RegistrationRateLimitRPM: 1, RegistrationRateLimitBurst: 1}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
    time.Sleep(300 * time.Millisecond)

    r := redis.NewClient(&redis.Options{Addr: addr})
    stream := cfg.Redis.KeyPrefix+"subject:register"
    respStream := cfg.Redis.KeyPrefix+"subject:resp:"+producerID

    // Payload
    var v any
    _ = json.Unmarshal([]byte(`{"op":"register","subject_key":"SR-2","schema_name":"s","schema_body":{}}`), &v)
    canon, _ := json.Marshal(v)

    // First request
    nonce1 := "sr-rl-1"
    sig1 := ed25519.Sign(priv, append([]byte(string(canon)), []byte("."+nonce1)...) )
    sig1B64 := base64.RawStdEncoding.EncodeToString(sig1)
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: stream, Values: map[string]any{"pubkey": pubLine, "payload": string(canon), "nonce": nonce1, "sig": sig1B64}}).Err(); err != nil { t.Fatalf("xadd1: %v", err) }
    _ = itutil.WaitReadStream(t, r, respStream, 10*time.Second)

    // Second immediate request should return error=rate_limited
    nonce2 := "sr-rl-2"
    sig2 := ed25519.Sign(priv, append([]byte(string(canon)), []byte("."+nonce2)...) )
    sig2B64 := base64.RawStdEncoding.EncodeToString(sig2)
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: stream, Values: map[string]any{"pubkey": pubLine, "payload": string(canon), "nonce": nonce2, "sig": sig2B64}}).Err(); err != nil { t.Fatalf("xadd2: %v", err) }

    // Wait latest response and assert error
    end := time.Now().Add(10 * time.Second)
    for time.Now().Before(end) { if l, _ := r.XLen(context.Background(), respStream).Result(); l >= 2 { break }; time.Sleep(100 * time.Millisecond) }
    last, _ := r.XRevRangeN(context.Background(), respStream, "+", "-", 1).Result()
    if len(last) == 0 { t.Fatalf("no response for rate-limited request") }
    if errStr, _ := last[0].Values["error"].(string); errStr != "rate_limited" { t.Fatalf("expected error=rate_limited, got %v", last[0].Values) }
}


