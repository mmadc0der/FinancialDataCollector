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

    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/auth"
)

func TestProducerProtocol_EndToEnd(t *testing.T) {
    if testing.Short() || getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }

    // deps
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    // Prepare DB & approve key fingerprint and create schema
    pg, err := data.NewPostgres(kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: true})
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    pool := pg.Pool()

    // keypair for registration/token issuance verification
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("keygen: %v", err) }
    pubLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(pub) + " it@test"
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
        Postgres: kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: false, BatchSize: 50, BatchMaxWaitMs: 50},
        Redis: kernelcfg.RedisConfig{Enabled: true, Addr: addr, KeyPrefix: "fdc:", ConsumerEnabled: true, Stream: "events"},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: privB64, PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    // wait ready
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    rcli := redis.NewClient(&redis.Options{Addr: addr})
    // 1) Registration: send and wait on per-nonce response
    payload := []byte(`{"producer_hint":"it","meta":{"env":"test"}}`)
    nonce := "0123456789abcdef"
    sum := sha3.Sum512(append(append([]byte{}, payload...), append([]byte{'.'}, []byte(nonce)...)...))
    sig := ed25519.Sign(priv, sum[:])
    sigB64 := base64.RawStdEncoding.EncodeToString(sig)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:register", Values: map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce, "sig": sigB64}}).Err(); err != nil {
        t.Fatalf("register xadd: %v", err)
    }
    waitFor[int64](t, 10*time.Second, func() (int64, bool) {
        l, _ := rcli.XLen(context.Background(), "fdc:register:resp:"+nonce).Result()
        return l, l >= 1
    })

    // 2) Token exchange: request and wait per-producer
    nonce2 := "abcdef0123456789"
    sum2 := sha3.Sum512([]byte("{}." + nonce2))
    sig2 := ed25519.Sign(priv, sum2[:])
    sig2B64 := base64.RawStdEncoding.EncodeToString(sig2)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:token:exchange", Values: map[string]any{"pubkey": pubLine, "payload": "{}", "nonce": nonce2, "sig": sig2B64}}).Err(); err != nil {
        t.Fatalf("exchange xadd: %v", err)
    }
    // fetch token
    tok := waitFor[string](t, 10*time.Second, func() (string, bool) {
        res, _ := rcli.XRead(context.Background(), &redis.XReadArgs{Streams: []string{"fdc:token:resp:"+producerID, "0-0"}, Count: 1, Block: 2 * time.Second}).Result()
        if len(res) == 0 { return "", false }
        if len(res[0].Messages) == 0 { return "", false }
        v, _ := res[0].Messages[0].Values["token"].(string)
        return v, v != ""
    })
    if tok == "" { t.Fatalf("empty token") }
    // verify token signature/claims
    ver, err := auth.NewVerifier(kernelcfg.AuthConfig{Enabled: true, RequireToken: true, Issuer: "it", Audience: "it", PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}}, pg, nil)
    if err != nil { t.Fatalf("verifier: %v", err) }
    sub, _, _, err := ver.Verify(context.Background(), tok)
    if err != nil || sub != producerID { t.Fatalf("verify token failed: %v sub=%s want=%s", err, sub, producerID) }

    // 3) Subject register with schema_id and wait per-producer
    subj := map[string]any{"subject_key": "IT-SUBJ-1", "schema_id": schemaID}
    b, _ := json.Marshal(subj)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:subject:register", Values: map[string]any{"payload": string(b), "token": tok}}).Err(); err != nil { t.Fatalf("subject xadd: %v", err) }
    sid := waitFor[string](t, 10*time.Second, func() (string, bool) {
        res, _ := rcli.XRead(context.Background(), &redis.XReadArgs{Streams: []string{"fdc:subject:resp:"+producerID, "0-0"}, Count: 1, Block: 2 * time.Second}).Result()
        if len(res) == 0 || len(res[0].Messages) == 0 { return "", false }
        v, _ := res[0].Messages[0].Values["subject_id"].(string)
        return v, v != ""
    })
    if sid == "" { t.Fatalf("empty subject_id") }

    // 4) Publish event accepted
    ev := map[string]any{"event_id":"it-evt-1", "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": sid, "payload": map[string]any{"kind":"test"}}
    evb, _ := json.Marshal(ev)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": ev["event_id"], "payload": string(evb), "token": tok}}).Err(); err != nil { t.Fatalf("event xadd: %v", err) }

    // 5) Deregister and ensure events are rejected to DLQ
    nonce3 := "feedfacecafebeef"
    sum3 := sha3.Sum512([]byte("{}." + nonce3))
    sig3 := ed25519.Sign(priv, sum3[:])
    sig3B64 := base64.RawStdEncoding.EncodeToString(sig3)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:register", Values: map[string]any{"action":"deregister", "pubkey": pubLine, "payload": "{}", "nonce": nonce3, "sig": sig3B64}}).Err(); err != nil {
        t.Fatalf("deregister xadd: %v", err)
    }
    waitFor[int64](t, 10*time.Second, func() (int64, bool) {
        l, _ := rcli.XLen(context.Background(), "fdc:register:resp:"+nonce3).Result()
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


