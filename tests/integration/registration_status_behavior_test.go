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

// Pending key: no response on per-nonce stream; audit row with status=pending; nonce guard set with TTL
func TestRegistration_Pending_NoResponse_AuditAndNonceGuard(t *testing.T) {
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

    // Insert pending key bound to a producer
    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'pending-prod') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'pending',$3) ON CONFLICT (fingerprint) DO UPDATE SET status='pending', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID); err != nil {
        t.Fatalf("upsert key: %v", err)
    }

    // Start kernel
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
    time.Sleep(300 * time.Millisecond)

    r := redis.NewClient(&redis.Options{Addr: addr})
    // Ensure group exists for register
    regStream := cfg.Redis.KeyPrefix+"register"
    endWait := time.Now().Add(5 * time.Second)
    for time.Now().Before(endWait) {
        groups, _ := r.XInfoGroups(context.Background(), regStream).Result()
        ready := false
        for _, g := range groups { if g.Name == cfg.Redis.ConsumerGroup { ready = true; break } }
        if ready { break }
        time.Sleep(100 * time.Millisecond)
    }

    payload := itutil.CanonicalizeJSON([]byte(`{"producer_hint":"pending","meta":{"env":"it"}}`))
    nonce := "pending-1"
    msg := append(append([]byte{}, payload...), []byte("."+nonce)...)
    sig := ed25519.Sign(priv, msg)
    sigB64 := base64.RawStdEncoding.EncodeToString(sig)
    values := map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce, "sig": sigB64}
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: regStream, Values: values}).Err(); err != nil { t.Fatalf("xadd: %v", err) }

    // Expect no response on per-nonce stream within 3s
    respStream := cfg.Redis.KeyPrefix+"register:resp:"+nonce
    deadline := time.Now().Add(3 * time.Second)
    sawResp := false
    for time.Now().Before(deadline) {
        if l, _ := r.XLen(context.Background(), respStream).Result(); l > 0 { sawResp = true; break }
        time.Sleep(100 * time.Millisecond)
    }
    if sawResp { t.Fatalf("unexpected response for pending key on %s", respStream) }

    // Audit row with status=pending
    var cnt int
    _ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.producer_registrations WHERE fingerprint=$1 AND nonce=$2 AND status='pending'`, fp, nonce).Scan(&cnt)
    if cnt < 1 { t.Fatalf("expected pending audit row") }

    // Nonce guard key set with TTL
    nonceKey := cfg.Redis.KeyPrefix+"reg:nonce:"+fp+":"+nonce
    itutil.WaitRedisKeyExists(t, r, nonceKey, 5*time.Second)
    if ttl, _ := r.TTL(context.Background(), nonceKey).Result(); ttl <= 0 { t.Fatalf("expected nonce TTL > 0, got %v", ttl) }
}

// Approved key: response on per-nonce stream; audit row with status=approved
func TestRegistration_Approved_ResponseAndAudit(t *testing.T) {
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

    // Insert approved key bound to a producer
    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'approved-prod') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID); err != nil {
        t.Fatalf("upsert key: %v", err)
    }

    // Start kernel
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
    time.Sleep(300 * time.Millisecond)

    r := redis.NewClient(&redis.Options{Addr: addr})
    // Ensure group exists for register
    regStream := cfg.Redis.KeyPrefix+"register"
    endWait := time.Now().Add(5 * time.Second)
    for time.Now().Before(endWait) {
        groups, _ := r.XInfoGroups(context.Background(), regStream).Result()
        ready := false
        for _, g := range groups { if g.Name == cfg.Redis.ConsumerGroup { ready = true; break } }
        if ready { break }
        time.Sleep(100 * time.Millisecond)
    }

    payload := itutil.CanonicalizeJSON([]byte(`{"producer_hint":"approved","meta":{"env":"it"}}`))
    nonce := "approved-1"
    msg := append(append([]byte{}, payload...), []byte("."+nonce)...)
    sig := ed25519.Sign(priv, msg)
    sigB64 := base64.RawStdEncoding.EncodeToString(sig)
    values := map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce, "sig": sigB64}
    if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: regStream, Values: values}).Err(); err != nil { t.Fatalf("xadd: %v", err) }

    // Expect response on per-nonce stream
    respStream := cfg.Redis.KeyPrefix+"register:resp:"+nonce
    m := itutil.WaitReadStream(t, r, respStream, 10*time.Second)
    if st, _ := m.Values["status"].(string); st != "approved" { t.Fatalf("expected status=approved, got %v", m.Values) }

    // Audit row with status=approved
    var cnt int
    _ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.producer_registrations WHERE fingerprint=$1 AND nonce=$2 AND status='approved'`, fp, nonce).Scan(&cnt)
    if cnt < 1 { t.Fatalf("expected approved audit row") }
}


