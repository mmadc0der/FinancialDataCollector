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

    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/auth"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestDuplicateEventID_SecondInsertIgnored(t *testing.T) {
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
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.schemas(schema_id,name,version,body) VALUES (gen_random_uuid(),'dupe',1,'{}'::jsonb) RETURNING schema_id`).Scan(&schemaID); err != nil { t.Fatalf("schema: %v", err) }
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'dupe-prod') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.subjects(subject_id,subject_key,attrs) VALUES (gen_random_uuid(),'DUPE-1','{}'::jsonb) RETURNING subject_id`).Scan(&subjectID); err != nil { t.Fatalf("subject: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.subject_schemas(subject_id,schema_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, subjectID, schemaID); err != nil { t.Fatalf("bind: %v", err) }
    if _, err := pool.Exec(context.Background(), `UPDATE public.subjects SET current_schema_id=$1 WHERE subject_id=$2`, schemaID, subjectID); err != nil { t.Fatalf("set current: %v", err) }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_subjects(producer_id,subject_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, producerID, subjectID); err != nil { t.Fatalf("bind ps: %v", err) }

    port := itutil.FreePort(t)
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    cfg := kernelcfg.Config{
        Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""),
        Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
        Logging:  kernelcfg.LoggingConfig{Level: "error"},
        Auth: kernelcfg.AuthConfig{Issuer: "it", Audience: "it", KeyID: "k", PrivateKey: base64.RawStdEncoding.EncodeToString(priv), PublicKeys: map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)}, ProducerSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it", AdminSSHCA: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it"},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    ver, _ := auth.NewVerifier(cfg.Auth, pg, nil)
    tok, _, _, _ := ver.IssueSubject(context.Background(), producerID, subjectID, time.Hour, "", "")

    r := redis.NewClient(&redis.Options{Addr: addr})
    evID := "dupe-evt-1"
    p := map[string]any{"event_id": evID, "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": subjectID, "payload": map[string]any{"k":"v"}}
    b, _ := json.Marshal(p)
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": evID, "payload": string(b), "token": tok}}).Err()
    // second time (duplicate id)
    _ = r.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id": evID, "payload": string(b), "token": tok}}).Err()

    time.Sleep(1 * time.Second)
    var cnt int
    _ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.event_index WHERE event_id=$1`, evID).Scan(&cnt)
    if cnt != 1 { t.Fatalf("expected 1 row for duplicate event_id, got %d", cnt) }
}
