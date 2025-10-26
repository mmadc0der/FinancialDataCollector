//go:build integration

package it

import (
	"context"
    "database/sql"
	"encoding/base64"
	"os"
	"strconv"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/sha3"
	ssh "golang.org/x/crypto/ssh"

	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
	itutil "github.com/example/data-kernel/tests/itutil"
)

func TestRegistrationReplay_RecordsAuditAndTTL(t *testing.T) {
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

    // Approve key for a producer
    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'reg-replay') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID); err != nil {
        t.Fatalf("upsert key: %v", err)
    }

    // Start kernel
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":"+strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "info"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine}}
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
    // Give consumers a brief moment to initialize before sending messages
    time.Sleep(600 * time.Millisecond)
    // Ensure registration consumer group is ready on the register stream
    regStream := cfg.Redis.KeyPrefix+"register"
    // Create redis client early for readiness polling
    r := redis.NewClient(&redis.Options{Addr: addr})
    endWait := time.Now().Add(5 * time.Second)
    for time.Now().Before(endWait) {
        groups, _ := r.XInfoGroups(context.Background(), regStream).Result()
        ready := false
        for _, g := range groups { if g.Name == cfg.Redis.ConsumerGroup { ready = true; break } }
        if ready { break }
        time.Sleep(100 * time.Millisecond)
    }

    // Send registration twice with same nonce
    nonce := "nonce-replay-1"
    payload := itutil.CanonicalizeJSON([]byte(`{"producer_hint":"rr","meta":{"x":"1"}}`))
    msg := append(append([]byte{}, payload...), []byte("."+nonce)...)
    sig := ed25519.Sign(priv, msg)
    sigB64 := base64.RawStdEncoding.EncodeToString(sig)
    values := map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce, "sig": sigB64}
    // regStream defined above
    respStream := cfg.Redis.KeyPrefix+"register:resp:"+nonce
    nonceKey := cfg.Redis.KeyPrefix+"reg:nonce:"+fp+":"+nonce
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: regStream, Values: values}).Err()
    // Ensure kernel processed the first registration by waiting for its response,
    // but if no response is emitted (e.g., pending), fall back to nonce key existence.
    waited := make(chan struct{}, 1)
    go func(){
        deadline := time.Now().Add(5 * time.Second)
        for time.Now().Before(deadline) {
            if l, _ := r.XLen(context.Background(), respStream).Result(); l >= 1 { waited <- struct{}{}; return }
            time.Sleep(100 * time.Millisecond)
        }
    }()
    select {
    case <-waited:
        // ok
    case <-time.After(5 * time.Second):
        itutil.WaitRedisKeyExists(t, r, nonceKey, 10*time.Second)
    }
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: regStream, Values: values}).Err()

    // Assert DB audit has replay record
    end := time.Now().Add(5 * time.Second)
    for time.Now().Before(end) {
        var n int
        _ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.producer_registrations WHERE fingerprint=$1 AND nonce=$2 AND status='replay'`, fp, nonce).Scan(&n)
        if n >= 1 { break }
        time.Sleep(100 * time.Millisecond)
    }
    var n int
    _ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.producer_registrations WHERE fingerprint=$1 AND nonce=$2 AND status='replay'`, fp, nonce).Scan(&n)
    if n < 1 {
        // Gather diagnostics to understand failure
        var total int
        _ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.producer_registrations WHERE fingerprint=$1`, fp).Scan(&total)
        // Status breakdown
        rows, _ := pool.Query(context.Background(), `SELECT status, COUNT(*) FROM public.producer_registrations WHERE fingerprint=$1 GROUP BY status`, fp)
        breakdown := map[string]int{}
        for rows.Next() { var st string; var c int; _ = rows.Scan(&st, &c); breakdown[st] = c }
        rows.Close()
        // Latest few entries
        latestRows, _ := pool.Query(context.Background(), `SELECT status, reason FROM public.producer_registrations WHERE fingerprint=$1 ORDER BY ts DESC LIMIT 3`, fp)
        latest := make([][2]string, 0, 3)
        for latestRows.Next() { var st, rs sql.NullString; _ = latestRows.Scan(&st, &rs); latest = append(latest, [2]string{st.String, rs.String}) }
        latestRows.Close()
        // Check TTL presence as well
        ttl, _ := r.TTL(context.Background(), cfg.Redis.KeyPrefix+"reg:nonce:"+fp+":"+nonce).Result()
        // Extra Redis diagnostics
        regLen, _ := r.XLen(context.Background(), regStream).Result()
        respLen, _ := r.XLen(context.Background(), respStream).Result()
        regGroups, _ := r.XInfoGroups(context.Background(), regStream).Result()
        // Last few messages (best-effort)
        regLast, _ := r.XRevRangeN(context.Background(), regStream, "+", "-", 5).Result()
        respLast, _ := r.XRevRangeN(context.Background(), respStream, "+", "-", 5).Result()
        t.Fatalf("expected replay audit row; total=%d breakdown=%v latest=%v ttl=%v regLen=%d respLen=%d regGroups=%v regLast=%v respLast=%v",
            total, breakdown, latest, ttl, regLen, respLen, regGroups, regLast, respLast)
    }

    // Assert nonce key TTL exists
    ttl, _ := r.TTL(context.Background(), nonceKey).Result()
    if ttl <= 0 { t.Fatalf("expected nonce TTL > 0, got %v", ttl) }
}


