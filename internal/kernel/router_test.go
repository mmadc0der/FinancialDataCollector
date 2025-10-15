package kernel

import (
    "encoding/json"
    "testing"
    "time"

    "github.com/example/data-kernel/internal/data"
)

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
	env1 := protocol.Envelope{ID: "e1", Version: "0.1.0", Type: "data", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"s":"A"}`)}
	env2 := protocol.Envelope{ID: "e2", Version: "0.1.0", Type: "data", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"s":"B"}`)}
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


