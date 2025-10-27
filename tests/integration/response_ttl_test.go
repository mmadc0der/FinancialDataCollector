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

// Verify TTL is set on register:resp:<nonce>, subject:resp:<producer_id>, token:resp:<producer_id>
func TestResponseStreams_TTL_Set_OnSuccess(t *testing.T) {
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
    fp := func(in []byte) string { h := sha3.Sum512(in); return base64.StdEncoding.EncodeToString(h[:]) }([]byte(pubLine))

    // Producer approved
    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'ttl') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    _, _ = pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID)

    // Start kernel with short TTL (e.g., 60s)
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine, RegistrationResponseTTLSeconds: 60}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
    time.Sleep(300 * time.Millisecond)

    r := redis.NewClient(&redis.Options{Addr: addr})

    // Registration response TTL
    regPayload := itutil.CanonicalizeJSON([]byte(`{"producer_hint":"ttl","meta":{"env":"it"}}`))
    regNonce := "ttl-reg-1"
    regSig := ed25519.Sign(priv, append([]byte(string(regPayload)), []byte("."+regNonce)...) )
    regSigB64 := base64.RawStdEncoding.EncodeToString(regSig)
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"register", Values: map[string]any{"pubkey": pubLine, "payload": string(regPayload), "nonce": regNonce, "sig": regSigB64}}).Err(); err != nil { t.Fatalf("xadd reg: %v", err) }
    itutil.WaitStreamLen(t, r, cfg.Redis.KeyPrefix+"register:resp:"+regNonce, 1, 10*time.Second)
    if ttl, _ := r.TTL(context.Background(), cfg.Redis.KeyPrefix+"register:resp:"+regNonce).Result(); ttl <= 0 { t.Fatalf("expected TTL on register:resp, got %v", ttl) }

    // Token response TTL
    nonceTok := "ttl-tok-1"
    sigTok := ed25519.Sign(priv, []byte("{}."+nonceTok))
    sigTokB64 := base64.RawStdEncoding.EncodeToString(sigTok)
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"token:exchange", Values: map[string]any{"pubkey": pubLine, "payload": "{}", "nonce": nonceTok, "sig": sigTokB64}}).Err(); err != nil { t.Fatalf("xadd tok: %v", err) }
    itutil.WaitStreamLen(t, r, cfg.Redis.KeyPrefix+"token:resp:"+producerID, 1, 10*time.Second)
    if ttl, _ := r.TTL(context.Background(), cfg.Redis.KeyPrefix+"token:resp:"+producerID).Result(); ttl <= 0 { t.Fatalf("expected TTL on token:resp, got %v", ttl) }

    // Subject response TTL
    subjPayload := itutil.CanonicalizeJSON([]byte(`{"op":"register","subject_key":"TTL-1","schema_name":"s","schema_body":{}}`))
    subjNonce := "ttl-sub-1"
    sigSub := ed25519.Sign(priv, append([]byte(string(subjPayload)), []byte("."+subjNonce)...) )
    sigSubB64 := base64.RawStdEncoding.EncodeToString(sigSub)
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix+"subject:register", Values: map[string]any{"pubkey": pubLine, "payload": string(subjPayload), "nonce": subjNonce, "sig": sigSubB64}}).Err(); err != nil { t.Fatalf("xadd subj: %v", err) }
    itutil.WaitStreamLen(t, r, cfg.Redis.KeyPrefix+"subject:resp:"+producerID, 1, 10*time.Second)
    if ttl, _ := r.TTL(context.Background(), cfg.Redis.KeyPrefix+"subject:resp:"+producerID).Result(); ttl <= 0 { t.Fatalf("expected TTL on subject:resp, got %v", ttl) }
}


