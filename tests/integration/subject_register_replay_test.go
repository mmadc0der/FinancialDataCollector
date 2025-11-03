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

	"golang.org/x/crypto/sha3"
	ssh "golang.org/x/crypto/ssh"

	"github.com/redis/go-redis/v9"

	"github.com/example/data-kernel/internal/data"
	"github.com/example/data-kernel/internal/kernelcfg"
	itutil "github.com/example/data-kernel/tests/itutil"
)

func TestSubjectRegister_ReplayProtection_ResponseAndTTL(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	itutil.WaitForPostgresReady(t, dsn, 10*time.Second)
	pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
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
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(cert))
	fp := func(in []byte) string { h := sha3.Sum512(in); return base64.StdEncoding.EncodeToString(h[:]) }([]byte(pubLine))

	// Insert approved key bound to a producer
	var producerID string
	if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'subr') RETURNING producer_id`).Scan(&producerID); err != nil {
		t.Fatalf("producer: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3) ON CONFLICT (fingerprint) DO UPDATE SET status='approved', producer_id=EXCLUDED.producer_id, pubkey=EXCLUDED.pubkey`, fp, pubLine, producerID); err != nil {
		t.Fatalf("upsert key: %v", err)
	}

	// Start kernel
	port := itutil.FreePort(t)
	cfg := kernelcfg.Config{Server: kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)}, Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""), Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerGroup: "kernel"}, Logging: kernelcfg.LoggingConfig{Level: "error"}, Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", ProducerSSHCA: caPubLine, AdminSSHCA: caPubLine}}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()
	itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)
	time.Sleep(300 * time.Millisecond)

	r := redis.NewClient(&redis.Options{Addr: addr})
	// Ensure group exists for subject:register
	stream := cfg.Redis.KeyPrefix + "subject:register"
	endWait := time.Now().Add(5 * time.Second)
	for time.Now().Before(endWait) {
		groups, _ := r.XInfoGroups(context.Background(), stream).Result()
		ready := false
		for _, g := range groups {
			if g.Name == cfg.Redis.ConsumerGroup {
				ready = true
				break
			}
		}
		if ready {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Prepare valid register payload
	var v any
	_ = json.Unmarshal([]byte(`{"op":"register","subject_key":"SR-1","schema_name":"s","schema_body":{}}`), &v)
	canon, _ := json.Marshal(v)
	nonce := "sr-nonce-1"
	msg := append(append([]byte{}, canon...), []byte("."+nonce)...)
	sig := ed25519.Sign(priv, msg)
	sigB64 := base64.RawStdEncoding.EncodeToString(sig)

	// First request
	if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: stream, Values: map[string]any{"pubkey": pubLine, "payload": string(canon), "nonce": nonce, "sig": sigB64}}).Err(); err != nil {
		t.Fatalf("xadd1: %v", err)
	}
	// Wait first response
	respStream := cfg.Redis.KeyPrefix + "subject:resp:" + producerID
	_ = itutil.WaitReadStream(t, r, respStream, 10*time.Second)

	// Replay with the same nonce
	if err := r.XAdd(context.Background(), &redis.XAddArgs{Stream: stream, Values: map[string]any{"pubkey": pubLine, "payload": string(canon), "nonce": nonce, "sig": sigB64}}).Err(); err != nil {
		t.Fatalf("xadd2: %v", err)
	}

	// Wait for at least 2 messages and assert last is error=replay
	end2 := time.Now().Add(10 * time.Second)
	for time.Now().Before(end2) {
		if l, _ := r.XLen(context.Background(), respStream).Result(); l >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	last, _ := r.XRevRangeN(context.Background(), respStream, "+", "-", 1).Result()
	if len(last) == 0 {
		t.Fatalf("no response after replay")
	}
	if errStr, _ := last[0].Values["error"].(string); errStr != "replay" {
		t.Fatalf("expected error=replay, got %v", last[0].Values)
	}

	// TTL on nonce key exists
	nonceKey := cfg.Redis.KeyPrefix + "nonce:subject:" + producerID + ":" + nonce
	if ttl, _ := r.TTL(context.Background(), nonceKey).Result(); ttl <= 0 {
		t.Fatalf("expected nonce TTL > 0, got %v", ttl)
	}
}
