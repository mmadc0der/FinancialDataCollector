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
    "encoding/json"

    "github.com/redis/go-redis/v9"
    "github.com/google/uuid"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestSchemaCacheMiss_BackfillsAndPersists(t *testing.T) {
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
    var schemaID, producerID, subjectID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.schemas(schema_id,name,version,body) VALUES (gen_random_uuid(),'cache-miss',1,'{}'::jsonb) RETURNING schema_id`).Scan(&schemaID); err != nil { t.Fatalf("schema: %v", err) }
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'cm-prod') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.subjects(subject_id,subject_key,attrs) VALUES (gen_random_uuid(),'CM-1','{}'::jsonb) RETURNING subject_id`).Scan(&subjectID); err != nil { t.Fatalf("subject: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.subject_schemas(subject_id,schema_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, subjectID, schemaID); err != nil { t.Fatalf("bind: %v", err) }
    if _, err := pool.Exec(context.Background(), `UPDATE public.subjects SET current_schema_id=$1 WHERE subject_id=$2`, schemaID, subjectID); err != nil { t.Fatalf("set current: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_subjects(producer_id,subject_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, producerID, subjectID); err != nil { t.Fatalf("bind ps: %v", err) }

    // Start kernel without pre-populating schema cache
    port := itutil.FreePort(t)
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("keygen: %v", err) }
    cfg := kernelcfg.Config{
        Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 100, ""),
        Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
        Logging:  kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{
            Issuer:   "it",
            Audience: "it",
            KeyID:    "k",
            PrivateKey: base64.RawStdEncoding.EncodeToString(priv),
            PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)},
            ProducerSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
            AdminSSHCA:    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
        },
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    // Issue token and publish event with schema cache miss
    ver, vErr := auth.NewVerifier(cfg.Auth, pg, nil)
    if vErr != nil { t.Fatalf("ver: %v", vErr) }
    tok, _, _, tErr := ver.IssueSubject(context.Background(), producerID, subjectID, time.Hour, "it", "")
    if tErr != nil { t.Fatalf("issue token: %v", tErr) }
    rcli := redis.NewClient(&redis.Options{Addr: addr})
    ev := map[string]any{"event_id": uuid.NewString(), "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": subjectID, "payload": map[string]any{"k":"v"}}
    b, _ := json.Marshal(ev)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": uuid.NewString(), "payload": string(b), "token": tok}}).Err(); err != nil { t.Fatalf("xadd: %v", err) }

    // Assert persisted to DB and cache key backfilled
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/healthz", 5*time.Second)
    ctx := context.Background()
    var cnt int
    _ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM public.event_index WHERE subject_id=$1`, subjectID).Scan(&cnt)
    if cnt < 1 { t.Fatalf("expected event persisted, got %d", cnt) }
    itutil.WaitRedisKeyExists(t, rcli, cfg.Redis.KeyPrefix+"schemas:"+subjectID, 5*time.Second)
}


