//go:build integration

package it

import (
    "context"
    "encoding/json"
    "net/http"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/redis/go-redis/v9"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernel"
    "github.com/example/data-kernel/internal/kernelcfg"
)

func TestIngestE2E_RedisToPostgres(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    // spin up deps
    pgc, dsn := startPostgres(t)
    defer pgc.Terminate(context.Background())
    rc, addr := startRedis(t)
    defer rc.Terminate(context.Background())

    // Prepare DB: apply migrations and create default schema/producer
    pg, err := data.NewPostgres(kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: true})
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    pool := pg.Pool()
    var schemaID, producerID string
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.schemas(schema_id,name,version,body) VALUES (gen_random_uuid(),'e2e',1,'{}'::jsonb) RETURNING schema_id`).Scan(&schemaID); err != nil {
        t.Fatalf("insert schema: %v", err)
    }
    if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'e2e-producer') RETURNING producer_id`).Scan(&producerID); err != nil {
        t.Fatalf("insert producer: %v", err)
    }

    // write a temp config file
    dir := t.TempDir()
    cfgPath := filepath.Join(dir, "kernel.yaml")
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":7600"},
        Postgres: kernelcfg.PostgresConfig{Enabled: true, DSN: dsn, ApplyMigrations: false, BatchSize: 10, BatchMaxWaitMs: 100, DefaultProducerID: producerID, DefaultSchemaID: schemaID},
        Redis: kernelcfg.RedisConfig{Enabled: true, Addr: addr, KeyPrefix: "fdc:", Stream: "events", ConsumerEnabled: true, PublishEnabled: false},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
    }
    b, _ := json.Marshal(cfg)
    if err := os.WriteFile(cfgPath, b, 0o644); err != nil { t.Fatalf("write cfg: %v", err) }

    // start kernel
    k, err := kernel.NewKernel(cfgPath)
    if err != nil { t.Fatalf("kernel new: %v", err) }
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    go func() { _ = k.Start(ctx) }()

    // wait for readyz
    waitFor[bool](t, 10*time.Second, func() (bool, bool) {
        resp, err := http.Get("http://127.0.0.1:7600/readyz")
        if err != nil { return false, false }
        defer resp.Body.Close()
        return resp.StatusCode == 200, resp.StatusCode == 200
    })

    // publish a message into Redis
    rcli := redis.NewClient(&redis.Options{Addr: addr})
    payload := []byte(`{"version":"0.1.0","type":"data","id":"01TEST","ts":1730000000000000000,"data":{"source":"test","symbol":"T"}}`)
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


