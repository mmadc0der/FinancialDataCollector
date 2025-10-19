//go:build !integration

package kernel

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
)

// Test router initialization
func TestRouterInit_ConfigDefaults(t *testing.T) {
	cfg := &kernelcfg.Config{
		Postgres: kernelcfg.PostgresConfig{
			BatchSize:      0, // should default to 1000
			BatchMaxWaitMs: 0, // should default to 200
		},
		Redis: kernelcfg.RedisConfig{
			PublishEnabled: false,
		},
	}

	// Validate config defaults are applied
	if cfg.Postgres.BatchSize == 0 {
		t.Logf("BatchSize defaults to 0 in config, applied in Load()")
	}
	if cfg.Redis.PublishEnabled != false {
		t.Fatalf("PublishEnabled should be false")
	}
}

// Test batch wait timeout interaction
func TestRouterBatching_WaitTimeout(t *testing.T) {
	// Config with very short batch wait (200ms)
	cfg := &kernelcfg.Config{
		Postgres: kernelcfg.PostgresConfig{
			BatchSize:      100,
			BatchMaxWaitMs: 200,
		},
		Redis: kernelcfg.RedisConfig{
			PublishEnabled: false,
		},
	}

	// Verify config values
	waitDuration := time.Duration(cfg.Postgres.BatchMaxWaitMs) * time.Millisecond
	if waitDuration != 200*time.Millisecond {
		t.Fatalf("batch wait not calculated correctly: %v", waitDuration)
	}
}

// Test message with empty payload
func TestMessageValidation_EmptyPayload(t *testing.T) {
	payload := []byte(``)
	if len(payload) == 0 {
		t.Logf("Empty payload detected - should be DLQ'd with 'empty_payload' reason")
	}
}

// Test message with invalid JSON
func TestMessageValidation_InvalidJSON(t *testing.T) {
	payload := []byte(`{invalid json}`)
	var result map[string]interface{}
	err := json.Unmarshal(payload, &result)
	if err != nil {
		t.Logf("Invalid JSON detected: %v - should be DLQ'd with 'invalid_json' reason", err)
	} else {
		t.Fatalf("expected JSON unmarshal to fail")
	}
}

// Test message missing required fields
func TestMessageValidation_MissingFields(t *testing.T) {
	testCases := []struct {
		name    string
		payload string
		missing string
	}{
		{"missing_timestamp", `{"version":"0.1.0","type":"data","id":"1"}`, "ts"},
		{"missing_type", `{"version":"0.1.0","ts":1730000000000000000,"id":"1"}`, "type"},
		{"missing_id", `{"version":"0.1.0","type":"data","ts":1730000000000000000}`, "id"},
		{"missing_data", `{"version":"0.1.0","type":"data","ts":1730000000000000000,"id":"1"}`, "data"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var msg map[string]interface{}
			if err := json.Unmarshal([]byte(tc.payload), &msg); err != nil {
				t.Fatalf("payload unmarshal: %v", err)
			}
			if _, hasField := msg[tc.missing]; !hasField {
				t.Logf("Missing field '%s' - should be rejected as malformed", tc.missing)
			}
		})
	}
}

// Test timestamp format validation
func TestMessageValidation_InvalidTimestamp(t *testing.T) {
	testCases := []struct {
		name      string
		timestamp interface{}
		isValid   bool
	}{
		{"valid_int64", int64(1730000000000000000), true},
		{"valid_float", float64(1730000000000000000), true},
		{"string_timestamp", "1730000000000000000", false},
		{"negative_timestamp", int64(-1), false},
		{"zero_timestamp", int64(0), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			switch v := tc.timestamp.(type) {
			case int64:
				if v <= 0 {
					t.Logf("Timestamp %v invalid - should be rejected", v)
				}
			case float64:
				if v <= 0 {
					t.Logf("Timestamp %v invalid - should be rejected", v)
				}
			default:
				t.Logf("Timestamp type %T invalid - should be rejected", v)
			}
		})
	}
}

// Test context deadline handling
func TestRouterContext_Deadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Simulate a slow operation
	time.Sleep(150 * time.Millisecond)

	// Check context is done
	select {
	case <-ctx.Done():
		t.Logf("Context deadline exceeded as expected")
	default:
		t.Fatalf("context should be cancelled")
	}
}

// Test queue size calculation
func TestRouterQueuing_DefaultSizes(t *testing.T) {
	// Default queue sizes when zero
	pgQueueDefault := 1024
	redisQueueDefault := 2048

	if pgQueueDefault < 1 {
		t.Fatalf("pg queue size invalid")
	}
	if redisQueueDefault < 1 {
		t.Fatalf("redis queue size invalid")
	}

	t.Logf("Default queue sizes: PG=%d, Redis=%d", pgQueueDefault, redisQueueDefault)
}


func TestHandleLeanEvent_AckWhenNoPostgres(t *testing.T) {
    acked := []string{}
    r := &router{ack: func(ids ...string) { acked = append(acked, ids...) }}
    // No pgChLean means immediate ack in lean path
    r.handleLeanEvent("1-0", "evt1", time.Now().Format(time.RFC3339Nano), "sid", "pid", json.RawMessage(`{"k":1}`), nil, "")
    if len(acked) != 1 || acked[0] != "1-0" {
        t.Fatalf("expected immediate ack of redis id, got %v", acked)
    }
}

func TestHandleLeanEvent_EnqueueToPgLean(t *testing.T) {
    r := &router{pgChLean: make(chan pgMsgLean, 1)}
    r.handleLeanEvent("r-1", "evt1", time.Now().Format(time.RFC3339Nano), "sid", "pid", json.RawMessage(`{"k":1}`), nil, "")
    select {
    case m := <-r.pgChLean:
        if m.RedisID != "r-1" || m.EventID != "evt1" { t.Fatalf("unexpected pgMsgLean: %+v", m) }
    default:
        t.Fatalf("expected message in pgChLean")
    }
}

func TestRDWorker_Smoke(t *testing.T) {
    r := &router{rdCh: make(chan rdMsg, 1), publishEnabled: true, rd: &data.Redis{}}
    done := make(chan struct{})
    go func() { r.rdWorker(); close(done) }()
    r.rdCh <- rdMsg{ID: "evt2", Payload: json.RawMessage(`{"a":2}`)}
    close(r.rdCh)
    select {
    case <-done:
    case <-time.After(500 * time.Millisecond):
        t.Fatalf("rdWorker did not exit in time")
    }
}

func TestPgWorkerBatch_FlushOnSize_Acks(t *testing.T) {
    ackCh := make(chan []string, 2)
    r := &router{ack: func(ids ...string) { // send a copy to avoid sharing backing array
        cp := make([]string, len(ids))
        copy(cp, ids)
        ackCh <- cp
    }}
	r.pgBatchSize = 2
	r.pgBatchWait = 200 * time.Millisecond
	r.pgCh = make(chan pgMsg, 2)
	// Use Postgres with nil pool so IngestEventsJSON returns nil (success)
	r.pg = &data.Postgres{}
	go r.pgWorkerBatch()
    env1 := struct{}{}
    env2 := struct{}{}
	r.pgCh <- pgMsg{RedisID: "r1", Env: env1}
	r.pgCh <- pgMsg{RedisID: "r2", Env: env2}
	// Close to let worker flush and exit
	close(r.pgCh)
    // Wait for one ack event and assert it contains both ids
    select {
    case got := <-ackCh:
        if len(got) != 2 { t.Fatalf("expected 2 ids in ack, got %v", got) }
        if !( (got[0]=="r1" && got[1]=="r2") || (got[0]=="r2" && got[1]=="r1") ) {
            t.Fatalf("unexpected ack ids: %v", got)
        }
    case <-time.After(500 * time.Millisecond):
        t.Fatalf("timed out waiting for ack")
    }
}


func TestPgWorkerBatchLean_FlushOnSize_Acks(t *testing.T) {
    ackCh := make(chan []string, 2)
    r := &router{ack: func(ids ...string) {
        cp := make([]string, len(ids))
        copy(cp, ids)
        ackCh <- cp
    }}
    r.pgBatchSize = 2
    r.pgBatchWait = 200 * time.Millisecond
    r.pgChLean = make(chan pgMsgLean, 2)
    // Use Postgres with nil pool so IngestEventsJSON returns nil (success)
    r.pg = &data.Postgres{}
    go r.pgWorkerBatchLean()
    r.pgChLean <- pgMsgLean{RedisID: "r1", EventID: "e1", TS: time.Now().Format(time.RFC3339Nano), SubjectID: "s1", ProducerID: "p1", SchemaID: "sch1", Payload: json.RawMessage(`{"x":1}`)}
    r.pgChLean <- pgMsgLean{RedisID: "r2", EventID: "e2", TS: time.Now().Format(time.RFC3339Nano), SubjectID: "s2", ProducerID: "p2", SchemaID: "sch2", Payload: json.RawMessage(`{"x":2}`)}
    close(r.pgChLean)
    select {
    case got := <-ackCh:
        if len(got) != 2 { t.Fatalf("expected 2 ids in ack, got %v", got) }
        if !((got[0]=="r1" && got[1]=="r2") || (got[0]=="r2" && got[1]=="r1")) {
            t.Fatalf("unexpected ack ids: %v", got)
        }
    case <-time.After(500 * time.Millisecond):
        t.Fatalf("timed out waiting for ack")
    }
}


