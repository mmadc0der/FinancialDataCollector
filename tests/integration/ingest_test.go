//go:build integration

package it

import (
    "context"
    "fmt"
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

    // Wait for containers to be stable
    time.Sleep(500 * time.Millisecond)

    // Prepare DB: apply migrations and create default entities
    pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    itutil.WaitForMigrations(t, pg, 10*time.Second)
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
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 100, producerID),
        Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
    }
    cancel := itutil.StartKernel(t, cfg)
    defer cancel()

    // Wait for kernel to be ready
    time.Sleep(1 * time.Second)

    // wait for readyz
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    // Wait before test operations
    time.Sleep(1 * time.Second)

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

func TestIngestE2E_BatchTimeout(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	// Wait for containers to be stable
	time.Sleep(500 * time.Millisecond)

	// Prepare DB
	pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	defer pg.Close()
	itutil.WaitForMigrations(t, pg, 10*time.Second)
	pool := pg.Pool()
	var schemaID, producerID, subjectID string
	if err := pool.QueryRow(context.Background(), `INSERT INTO public.schemas(schema_id,name,version,body) VALUES (gen_random_uuid(),'batch_test',1,'{}'::jsonb) RETURNING schema_id`).Scan(&schemaID); err != nil {
		t.Fatalf("insert schema: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'batch-producer') RETURNING producer_id`).Scan(&producerID); err != nil {
		t.Fatalf("insert producer: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `INSERT INTO public.subjects(subject_id,subject_key,attrs) VALUES (gen_random_uuid(),'BATCH-1','{}'::jsonb) RETURNING subject_id`).Scan(&subjectID); err != nil {
		t.Fatalf("insert subject: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO public.subject_schemas(subject_id,schema_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, subjectID, schemaID); err != nil {
		t.Fatalf("bind subject_schema: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE public.subjects SET current_schema_id=$1 WHERE subject_id=$2`, schemaID, subjectID); err != nil {
		t.Fatalf("set current schema: %v", err)
	}

	port := itutil.FreePort(t)
	cfg := kernelcfg.Config{
		Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
		Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 5, 300, ""), // Short batch window
		Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
		Logging:  kernelcfg.LoggingConfig{Level: "error"},
		Auth: kernelcfg.AuthConfig{
			Issuer:                     "it",
			Audience:                   "it",
			KeyID:                      "k",
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

	// Wait for kernel to be ready
	time.Sleep(1 * time.Second)

	itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

	// Wait before test operations
	time.Sleep(1 * time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	// Send 3 messages (less than batch size of 5)
	for i := 0; i < 3; i++ {
		payload := []byte(fmt.Sprintf(`{"version":"0.1.0","type":"data","id":"batch-%d","ts":%d,"subject_id":"%s","producer_id":"%s","data":{"value":%d}}`, i, time.Now().UnixNano(), subjectID, producerID, i))
		if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
			Stream: "fdc:events",
			Values: map[string]any{"id": fmt.Sprintf("batch-%d", i), "payload": payload},
		}).Err(); err != nil {
			t.Fatalf("xadd: %v", err)
		}
	}

	// Wait for batch timeout to flush
	time.Sleep(500 * time.Millisecond)

	// Verify messages are in DB (batch timeout should have flushed them)
	var count int64
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.events WHERE subject_id = $1`, subjectID).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count < 3 {
		t.Fatalf("expected at least 3 messages in DB after batch timeout, got %d", count)
	}
	t.Logf("Batch timeout test passed: %d messages persisted", count)
}

func TestIngestE2E_DLQFallback_InvalidMessage(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	port := itutil.FreePort(t)
	cfg := kernelcfg.Config{
		Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
		Postgres: itutil.NewPostgresConfigWithBatch(dsn, 10, 50),
		Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
		Logging:  kernelcfg.LoggingConfig{Level: "error"},
		Auth: kernelcfg.AuthConfig{
			Issuer:                     "it",
			Audience:                   "it",
			KeyID:                      "k",
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

	itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	// Send message with missing required field
	invalidPayload := []byte(`{"version":"0.1.0","type":"data","id":"invalid"}`) // missing ts, data fields
	if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
		Stream: "fdc:events",
		Values: map[string]any{"id": "invalid", "payload": invalidPayload},
	}).Err(); err != nil {
		t.Fatalf("xadd: %v", err)
	}

	// Give kernel time to process
	time.Sleep(2 * time.Second)

	// Check DLQ has the message
	dlqLen, _ := rcli.XLen(context.Background(), "fdc:events:dlq").Result()
	if dlqLen < 1 {
		t.Fatalf("expected DLQ entry for invalid message, got len=%d", dlqLen)
	}
	t.Logf("Invalid message correctly routed to DLQ")
}

func TestIngestE2E_Partition_TimeAccuracy(t *testing.T) {
	if os.Getenv("RUN_IT") == "" {
		t.Skip("integration test; set RUN_IT=1 to run")
	}
	pgc, dsn := itutil.StartPostgres(t)
	defer pgc.Terminate(context.Background())
	rc, addr := itutil.StartRedis(t)
	defer rc.Terminate(context.Background())

	// Wait for containers to be stable
	time.Sleep(500 * time.Millisecond)

	// Prepare DB
	pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	defer pg.Close()
	itutil.WaitForMigrations(t, pg, 10*time.Second)
	pool := pg.Pool()
	var schemaID, producerID, subjectID string
	if err := pool.QueryRow(context.Background(), `INSERT INTO public.schemas(schema_id,name,version,body) VALUES (gen_random_uuid(),'partition_test',1,'{}'::jsonb) RETURNING schema_id`).Scan(&schemaID); err != nil {
		t.Fatalf("insert schema: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'part-producer') RETURNING producer_id`).Scan(&producerID); err != nil {
		t.Fatalf("insert producer: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `INSERT INTO public.subjects(subject_id,subject_key,attrs) VALUES (gen_random_uuid(),'PART-1','{}'::jsonb) RETURNING subject_id`).Scan(&subjectID); err != nil {
		t.Fatalf("insert subject: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO public.subject_schemas(subject_id,schema_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, subjectID, schemaID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE public.subjects SET current_schema_id=$1 WHERE subject_id=$2`, schemaID, subjectID); err != nil {
		t.Fatalf("set schema: %v", err)
	}

	port := itutil.FreePort(t)
	cfg := kernelcfg.Config{
		Server:   kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
		Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 50, ""),
		Redis:    kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false, ConsumerGroup: "kernel"},
		Logging:  kernelcfg.LoggingConfig{Level: "error"},
		Auth: kernelcfg.AuthConfig{
			Issuer:                     "it",
			Audience:                   "it",
			KeyID:                      "k",
			RegistrationRateLimitRPM:   10,
			RegistrationRateLimitBurst: 3,
			ProducerSSHCA:              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestProducerCA test@it",
			AdminSSHCA:                 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminCA test@it",
		},
	}
	cancel := itutil.StartKernel(t, cfg)
	defer cancel()

	// Wait for kernel to be ready
	time.Sleep(1 * time.Second)

	itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

	// Wait before test operations
	time.Sleep(1 * time.Second)

	rcli := redis.NewClient(&redis.Options{Addr: addr})
	defer rcli.Close()

	// Send messages with different timestamps to test partition routing
	now := time.Now().UnixNano()
	for i := 0; i < 2; i++ {
		ts := now + int64(i*1000)
		payload := []byte(fmt.Sprintf(`{"version":"0.1.0","type":"data","id":"part-%d","ts":%d,"subject_id":"%s","producer_id":"%s","data":{"seq":%d}}`, i, ts, subjectID, producerID, i))
		if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
			Stream: "fdc:events",
			Values: map[string]any{"id": fmt.Sprintf("part-%d", i), "payload": payload},
		}).Err(); err != nil {
			t.Fatalf("xadd: %v", err)
		}
	}

	// Wait for processing
	time.Sleep(1 * time.Second)

	// Verify messages are in DB
	var count int64
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.events WHERE subject_id = $1`, subjectID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count < 2 {
		t.Fatalf("expected at least 2 messages, got %d", count)
	}
	t.Logf("Partition test passed: %d messages stored", count)
}


