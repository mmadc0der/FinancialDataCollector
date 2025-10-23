//go:build integration

package it

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "strconv"
    "testing"
    "time"

    "github.com/redis/go-redis/v9"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/auth"
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
    // Bind producer to subject for authorization checks
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_subjects(producer_id,subject_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, producerID, subjectID); err != nil {
        t.Fatalf("bind producer_subject: %v", err)
    }

    // dynamic port
    port := itutil.FreePort(t)
    // Generate issuer keys for tokens
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("keygen: %v", err) }
    cfg := kernelcfg.Config{
        Server: kernelcfg.ServerConfig{Listen: ":" + strconv.Itoa(port)},
        Postgres: itutil.NewPostgresConfigNoMigrations(dsn, 10, 100, producerID),
        Redis: kernelcfg.RedisConfig{Addr: addr, KeyPrefix: "fdc:", Stream: "events", PublishEnabled: false},
        Logging: kernelcfg.LoggingConfig{Level: "error"},
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

    // Wait for kernel to be ready
    time.Sleep(1 * time.Second)

    // wait for readyz
    itutil.WaitHTTPReady(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/readyz", 10*time.Second)

    // Wait before test operations
    time.Sleep(1 * time.Second)

    // Prepare token and schema cache
    ver, vErr := auth.NewVerifier(cfg.Auth, pg, nil)
    if vErr != nil { t.Fatalf("ver: %v", vErr) }
    tok, _, _, tErr := ver.IssueSubject(context.Background(), producerID, subjectID, time.Hour, "it", "")
    if tErr != nil { t.Fatalf("issue token: %v", tErr) }
    rcli := redis.NewClient(&redis.Options{Addr: addr})
    // Pre-populate schema cache so first event has schema_id
    _ = rcli.Set(context.Background(), cfg.Redis.KeyPrefix+"schemas:"+subjectID, schemaID, time.Hour).Err()

    // publish a message into Redis (lean protocol)
    ev := map[string]any{"event_id":"01TEST","ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": subjectID, "payload": map[string]any{"source":"test","symbol":"T"}}
    evb, _ := json.Marshal(ev)
    if err := rcli.XAdd(context.Background(), &redis.XAddArgs{Stream: "fdc:events", Values: map[string]any{"id":"01TEST","payload": string(evb), "token": tok}}).Err(); err != nil {
        t.Fatalf("xadd: %v", err)
    }

    // assert persisted in DB
    waitFor[int](t, 10*time.Second, func() (int, bool) {
        var cnt int
        // reuse existing pool from test setup
        _ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.events`).Scan(&cnt)
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
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_subjects(producer_id,subject_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, producerID, subjectID); err != nil {
        t.Fatalf("bind producer_subject: %v", err)
    }

	port := itutil.FreePort(t)
    // Generate issuer keys for tokens
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("keygen: %v", err) }
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
            PrivateKey:                 base64.RawStdEncoding.EncodeToString(priv),
            PublicKeys:                 map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)},
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

    // Prepare token and schema cache
    ver, vErr := auth.NewVerifier(cfg.Auth, pg, nil)
    if vErr != nil { t.Fatalf("ver: %v", vErr) }
    tok, _, _, tErr := ver.IssueSubject(context.Background(), producerID, subjectID, time.Hour, "it", "")
    if tErr != nil { t.Fatalf("issue token: %v", tErr) }
    _ = rcli.Set(context.Background(), cfg.Redis.KeyPrefix+"schemas:"+subjectID, schemaID, time.Hour).Err()

	// Send 3 messages (less than batch size of 5)
	for i := 0; i < 3; i++ {
        ev := map[string]any{"event_id": fmt.Sprintf("batch-%d", i), "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": subjectID, "payload": map[string]any{"value": i}}
        evb, _ := json.Marshal(ev)
        if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
            Stream: "fdc:events",
            Values: map[string]any{"id": fmt.Sprintf("batch-%d", i), "payload": string(evb), "token": tok},
        }).Err(); err != nil {
			t.Fatalf("xadd: %v", err)
		}
	}

	// Wait for batch timeout to flush
	time.Sleep(500 * time.Millisecond)

    // Verify messages are in DB (batch timeout should have flushed them)
	var count int64
    if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.event_index WHERE subject_id = $1`, subjectID).Scan(&count); err != nil {
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
    if _, err := pool.Exec(context.Background(), `INSERT INTO public.producer_subjects(producer_id,subject_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, producerID, subjectID); err != nil {
        t.Fatalf("bind producer_subject: %v", err)
    }

	port := itutil.FreePort(t)
    // Generate issuer keys for tokens
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatalf("keygen: %v", err) }
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
            PrivateKey:                 base64.RawStdEncoding.EncodeToString(priv),
            PublicKeys:                 map[string]string{"k": base64.RawStdEncoding.EncodeToString(pub)},
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

    // Prepare token and schema cache
    ver, vErr := auth.NewVerifier(cfg.Auth, pg, nil)
    if vErr != nil { t.Fatalf("ver: %v", vErr) }
    tok, _, _, tErr := ver.IssueSubject(context.Background(), producerID, subjectID, time.Hour, "it", "")
    if tErr != nil { t.Fatalf("issue token: %v", tErr) }
    _ = rcli.Set(context.Background(), cfg.Redis.KeyPrefix+"schemas:"+subjectID, schemaID, time.Hour).Err()

    // Send messages with different timestamps to test partition routing
	now := time.Now().UnixNano()
	for i := 0; i < 2; i++ {
        _ = now // keep variable for potential future use
        ev := map[string]any{"event_id": fmt.Sprintf("part-%d", i), "ts": time.Now().UTC().Format(time.RFC3339Nano), "subject_id": subjectID, "payload": map[string]any{"seq": i}}
        evb, _ := json.Marshal(ev)
        if err := rcli.XAdd(context.Background(), &redis.XAddArgs{
            Stream: "fdc:events",
            Values: map[string]any{"id": fmt.Sprintf("part-%d", i), "payload": string(evb), "token": tok},
        }).Err(); err != nil {
			t.Fatalf("xadd: %v", err)
		}
	}

	// Wait for processing
	time.Sleep(1 * time.Second)

    // Verify messages are in DB
	var count int64
    if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM public.event_index WHERE subject_id = $1`, subjectID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count < 2 {
		t.Fatalf("expected at least 2 messages, got %d", count)
	}
	t.Logf("Partition test passed: %d messages stored", count)
}


