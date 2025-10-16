//go:build integration

package it

import (
    "context"
    "os"
    "strconv"
    "testing"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestIngestE2E_RedisToPostgres(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    // spin up deps
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := itutil.StartRedis(t)
    defer rc.Terminate(context.Background())

    // Prepare DB: apply migrations and create default entities
    pg, err := data.NewPostgres(kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: true})
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    pool := pg.Pool()
    var schemaID, producerID, subjectID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.schemas(schema_id,name,version,body) VALUES (gen_random_uuid(),'e2e',1,'{}'::jsonb) RETURNING schema_id`).Scan(&schemaID); err != nil {
        t.Fatalf("insert schema: %v", err)
    }
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'e2e-producer') RETURNING producer_id`).Scan(&producerID); err != nil {
        t.Fatalf("insert producer: %v", err)
    }
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.subjects(subject_id,subject_key,attrs) VALUES (gen_random_uuid(),'IT-1','{}'::jsonb) RETURNING subject_id`).Scan(&subjectID); err != nil {
        t.Fatalf("insert subject: %v", err)
    }
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.subject_schemas(subject_id,schema_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, subjectID, schemaID); err != nil {
        t.Fatalf("bind subject_schema: %v", err)
    }
    if _, err := pool.Exec(context.Background(), `UPDATE public.subjects SET current_schema_id=$1 WHERE subject_id=$2`, schemaID, subjectID); err != nil {
        t.Fatalf("set current schema: %v", err)
    }

    // dynamic port
    port := itutil.FreePort(t)
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: false, BatchSize: 10, BatchMaxWaitMs: 100, DefaultProducerID: producerID},
        Redis: kernelcfg.RedisConfig{Enabled: true, Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerEnabled: true, PublishEnabled: false},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    // wait for readyz
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    // publish a message into Redis
    rcli := redis.NewClient(&redis.Options{Addr: addr})
    payload := []byte(`{"event_id":"01TEST","ts":"2024-10-01T00:00:00Z","subject_id":"` + subjectID + `","payload":{"source":"test","symbol":"T"}}`)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id":"01TEST","payload": payload}}).Err(); err != nil {
        t.Fatalf("xadd: %v", err)
    }

    // assert persisted in DB
    waitFor[int](t, 10*time.Second, func() (int, bool) {
        var cnt int
        // new pool to avoid stale conn
        p, _ := pgxpool.New(context.Background(), dsn)
        defer p.Close()
        _ = p.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.events`).Scan(&cnt)
        return cnt, cnt >= 1
    })
}


