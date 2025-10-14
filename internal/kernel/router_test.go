package kernel

import (
    "encoding/json"
    "testing"
    "time"

    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/data"
)

func TestHandleRedis_AckWhenNoPostgres(t *testing.T) {
	acked := []string{}
	r := &router{ack: func(ids ...string) { acked = append(acked, ids...) }}
	// No Postgres channel means immediate ack
	r.handleRedis("1-0", protocol.Envelope{ID: "evt1", Version: "0.1.0", Type: "data", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"k":1}`)})
	if len(acked) != 1 || acked[0] != "1-0" {
		t.Fatalf("expected immediate ack of redis id, got %v", acked)
	}
}

func TestHandleRedis_EnqueueToPg(t *testing.T) {
	r := &router{pgCh: make(chan pgMsg, 1)}
	r.handleRedis("r-1", protocol.Envelope{ID: "evt1", Version: "0.1.0", Type: "data", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"k":1}`)})
	select {
	case m := <-r.pgCh:
		if m.RedisID != "r-1" || m.Env.ID != "evt1" { t.Fatalf("unexpected pgMsg: %+v", m) }
	default:
		t.Fatalf("expected message in pgCh")
	}
}

func TestHandleRedis_PublishEnqueue(t *testing.T) {
	r := &router{rdCh: make(chan rdMsg, 1), publishEnabled: true}
	env := protocol.Envelope{ID: "evt2", Version: "0.1.0", Type: "data", TS: time.Now().UnixNano(), Data: json.RawMessage(`{"a":2}`)}
	r.handleRedis("r-2", env)
	select {
	case m := <-r.rdCh:
		if m.ID != "evt2" { t.Fatalf("unexpected rdMsg id: %s", m.ID) }
		var got protocol.Envelope
		_ = json.Unmarshal(m.Payload, &got)
		if got.ID != env.ID || string(got.Data) != string(env.Data) { t.Fatalf("payload mismatch: %+v vs %+v", got, env) }
	default:
		t.Fatalf("expected message in rdCh")
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


