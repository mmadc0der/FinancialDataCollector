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
	"strings"

	"golang.org/x/crypto/sha3"
	ssh "golang.org/x/crypto/ssh"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/example/data-kernel/internal/auth"
	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
	itutil "github.com/example/data-kernel/tests/itutil"
)

func TestProducerProtocol_EndToEnd(t *testing.T) {
    if testing.Short() || getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }

    // deps
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    // Wait for containers to be stable
    time.Sleep(500 * time.Millisecond)

    // Ensure Postgres is accepting connections and pre-apply migrations
    itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

    // Prepare DB & approve key fingerprint and create schema
    pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    itutil.WaitForMigrations(t, pg, 10*time.Second)
    pool := pg.Pool()

    // Generate CA (for SSH certificate) and producer keypair
    _, caPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("ca keygen: %v", err) }
    caSigner, err := ssh.NewSignerFromKey(caPriv)
    if err != nil { t.Fatalf("ca signer: %v", err) }
    caPubLine := string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))

    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("keygen: %v", err) }
    // Make SSH certificate for producer key, signed by CA
    prodPub, err := ssh.NewPublicKey(pub)
    if err != nil { t.Fatalf("ssh pub: %v", err) }
    cert := &ssh.Certificate{
        Key:             prodPub,
        Serial:          1,
        CertType:        ssh.UserCert,
        KeyId:           "it",
        ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
        ValidBefore:     uint64(time.Now().Add(1 * time.Hour).Unix()),
        Permissions:     ssh.Permissions{},
    }
    if err := cert.SignCert(rand.Reader, caSigner); err != nil { t.Fatalf("sign cert: %v", err) }
    pubLine := string(ssh.MarshalAuthorizedKey(cert))
    fp := func(in []byte) string { h := sha3.Sum512(in); return base64.StdEncoding.EncodeToString(h[:]) }([]byte(pubLine))

    // create producer and bind key as approved
    var producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'it-prod') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID); err != nil {
        t.Fatalf("upsert key: %v", err)
    }
    // create schema to set as current for subject
    var schemaID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.schemas(schema_id,name,version,body) VALUES (gen_random_uuid(),'it-schema',1,'{}'::jsonb) RETURNING schema_id`).Scan(&schemaID); err != nil { t.Fatalf("schema: %v", err) }

    // start kernel with auth (private key to issue tokens)
    privB64 := base64.RawStdEncoding.EncodeToString(append([]byte{}, priv...))
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 50, 50, ""),
        Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: true, ConsumerGroup: "kernel"},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{
            RequireToken: true,
            Issuer: "it",
            Audience: "it",
            KeyID: "k",
            PrivateKey: privB64,
            PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)},
            ProducerSSHCA: strings.TrimSpace(caPubLine),
            AdminSSHCA: strings.TrimSpace(caPubLine),
        },
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    // Wait for kernel to be ready
    time.Sleep(1 * time.Second)

    // wait ready
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 20*time.Second)

    // Wait before test operations
    time.Sleep(1 * time.Second)

    rcli := redis.NewClient(&redis.Options{Addr: addr})
    // 1) Registration: send and wait on per-nonce response
    payload := []byte(`{"producer_hint":"it","meta":{"env":"test"}}`)
    // Canonicalize JSON like the server does before signing
    var payloadTmp any
    _ = json.Unmarshal(payload, &payloadTmp)
    canon, _ := json.Marshal(payloadTmp)
    nonce := "0123456789abcdef"
    msg := append(canon, []byte("."+nonce)...)
    sig := ed25519.Sign(priv, msg)
    sigB64 := base64.RawStdEncoding.EncodeToString(sig)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix + "register", Values: map[string]any{"pubkey": pubLine, "payload": string(canon), "nonce": nonce, "sig": sigB64}}).Err(); err != nil {
        t.Fatalf("register xadd: %v", err)
    }
    waitFor[int64](t, 10*time.Second, func() (int64, bool) {
        l, _ := rcli.XLen(context.Background(), cfg.Redis.KeyPrefix + "register:resp:"+nonce).Result()
        return l, l >= 1
    })

    // 2) Token exchange: request and wait per-producer
    nonce2 := "abcdef0123456789"
    msg2 := []byte("{}." + nonce2)
    sig2 := ed25519.Sign(priv, msg2)
    sig2B64 := base64.RawStdEncoding.EncodeToString(sig2)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix + "token:exchange", Values: map[string]any{"pubkey": pubLine, "payload": "{}", "nonce": nonce2, "sig": sig2B64}}).Err(); err != nil {
        t.Fatalf("exchange xadd: %v", err)
    }
    // fetch token
    tok := waitFor[string](t, 10*time.Second, func() (string, bool) {
        res, _ := rcli.XRead(context.Background(), &redis.XReadArgs{Streams: []string{cfg.Redis.KeyPrefix + "token:resp:"+producerID, "0-0"}, Count: 1, Block: 2 * time.Second}).Result()
        if len(res) == 0 { return "", false }
        if len(res[0].Messages) == 0 { return "", false }
        v, _ := res[0].Messages[0].Values["token"].(string)
        return v, v != ""
    })
    if tok == "" { t.Fatalf("empty token") }
    // verify token signature/claims
    ver, err := auth.NewVerifier(kernelcfg.AuthConfig{RequireToken: true, Issuer: "it", Audience: "it", PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}}, pg, nil)
    if err != nil { t.Fatalf("verifier: %v", err) }
    sub, _, _, err := ver.Verify(context.Background(), tok)
    if err != nil || sub != producerID { t.Fatalf("verify token failed: %v sub=%s want=%s", err, sub, producerID) }

    // 3) Subject register using signed pubkey (protocol expects pubkey+sig)
    var subjTmp any
    _ = json.Unmarshal([]byte(`{"op":"register", "subject_key": "IT-SUBJ-1", "schema_name": "it-schema", "schema_body": {}}`), &subjTmp)
    subjCanon, _ := json.Marshal(subjTmp)
    nonceS := "subj-nonce-001"
    msgS := append(subjCanon, []byte("."+nonceS)...)
    sigS := ed25519.Sign(priv, msgS)
    sigSB64 := base64.RawStdEncoding.EncodeToString(sigS)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix + "subject:register", Values: map[string]any{"pubkey": pubLine, "payload": string(subjCanon), "nonce": nonceS, "sig": sigSB64}}).Err(); err != nil { t.Fatalf("subject xadd: %v", err) }
    subjRespStream := cfg.Redis.KeyPrefix + "subject:resp:" + producerID
    // Read a response message and surface any errors for debugging
    msg := itutil.WaitReadStream(t, rcli, subjRespStream, 15*time.Second)
    if errStr, _ := msg.Values["error"].(string); errStr != "" {
        t.Fatalf("subject register error: %s values=%v", errStr, msg.Values)
    }
    sid, _ := msg.Values["subject_id"].(string)
    if sid == "" { t.Fatalf("empty subject_id values=%v", msg.Values) }

    // 4) Publish event accepted (lean protocol)
    ev := map[string]any{"event_id": uuid.NewString(), "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": sid, "payload": map[string]any{"kind":"test"}}
    evb, _ := json.Marshal(ev)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": ev["event_id"], "payload": string(evb), "token": tok}}).Err(); err != nil { t.Fatalf("event xadd: %v", err) }

    // 5) Deregister and ensure events are rejected to DLQ
    nonce3 := "feedfacecafebeef"
    msg3 := []byte("{}." + nonce3)
    sig3 := ed25519.Sign(priv, msg3)
    sig3B64 := base64.RawStdEncoding.EncodeToString(sig3)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix + "register", Values: map[string]any{"action":"deregister", "pubkey": pubLine, "payload": "{}", "nonce": nonce3, "sig": sig3B64}}).Err(); err != nil {
        t.Fatalf("deregister xadd: %v", err)
    }
    waitFor[int64](t, 10*time.Second, func() (int64, bool) {
        l, _ := rcli.XLen(context.Background(), cfg.Redis.KeyPrefix + "register:resp:"+nonce3).Result()
        return l, l >= 1
    })
    // publish again -> DLQ
    _ = rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": "it-evt-2", "payload": string(evb), "token": tok}}).Err()
    waitFor[int64](t, 10*time.Second, func() (int64, bool) {
        l, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
        return l, l >= 1
    })
}

func getenv(k string) string { return os.Getenv(k) }


