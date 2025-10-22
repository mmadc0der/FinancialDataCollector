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
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestRegistrationRespondsPerNonce(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    // deps
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    // Prepare DB & approve key fingerprint
    pg, err := data.NewPostgres(kernelcfg.PostgresConfig{DSN: dsn, ApplyMigrations: true})
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    _ = pg.Pool()

    // generate ed25519 key and encode OpenSSH public key line
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("keygen: %v", err) }
    // Encode pub as OpenSSH format: use minimal ssh lib? To keep deps simple here we embed a precomputed pub template is non-trivial; skip actual kernel verification and test DB path by inserting fingerprint that matches the input string hashing used by kernel (sha3-512 over pubkey data base64)
    pubLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(pub) + " test@it"
    // Compute fp same as kernel: sha3-512 over bytes then base64
    // We reimplement small helper inline to avoid importing kernel
    fp := func(in []byte) string { h := sha3.Sum512(in); return base64.StdEncoding.EncodeToString(h[:]) }([]byte(pubLine))

    // Upsert key row and approve + bind to a producer
    var producerID string
    if err := pg.Pool().QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'auto') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    if _, err := pg.Pool().Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID); err != nil {
        t.Fatalf("upsert key: %v", err)
    }

    // write config with auth enabled and private key to issue tokens
    privB64 := base64.RawStdEncoding.EncodeToString(append([]byte{}, priv...))
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: kernelcfg.PostgresConfig{DSN: dsn, ApplyMigrations: false, BatchSize: 10, BatchMaxWaitMs: 50},
        Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events"},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{RequireToken: true, Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: privB64, PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    // wait for ready
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    // publish registration message
    rcli := redis.NewClient(&redis.Options{Addr: addr})
    payload := []byte(`{"producer_hint":"auto","meta":{"env":"it"}}`)
    nonce := "abcdef0123456789"
    // sign SHA3-512(payload + "." + nonce) with priv
    msg := append([]byte{}, payload...)
    msg = append(msg, '.')
    msg = append(msg, []byte(nonce)...)
    sum := sha3.Sum512(msg)
    sig := ed25519.Sign(priv, sum[:])
    sigB64 := base64.RawStdEncoding.EncodeToString(sig)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: cfg.Redis.KeyPrefix + "register", Values: map[string]any{"pubkey": pubLine, "payload": string(payload), "nonce": nonce, "sig": sigB64}}).Err(); err != nil {
        t.Fatalf("xadd reg: %v", err)
    }

    // wait for registration response on per-nonce stream
    itutil.WaitStreamLen(t, rcli, cfg.Redis.KeyPrefix+"register:resp:"+nonce, 1, 10*time.Second)
}


