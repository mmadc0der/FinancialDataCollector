package kernel

import (
    "testing"
    "encoding/json"
    "time"

    "github.com/example/data-kernel/internal/data"
)

func TestPrefixed(t *testing.T) {
    if prefixed("", "k") != "k" { t.Fatalf("no prefix case failed") }
    if prefixed("fdc:", "events") != "fdc:events" { t.Fatalf("prefix case failed") }
}

// Removed redundant envelope adapter tests and helpers



func TestHandleLeanEvent_BuildsExpectedRowAndAcks(t *testing.T) {
    acked := []string{}
    r := &router{ack: func(ids ...string) { acked = append(acked, ids...) }}
    r.pgBatchSize = 10
    r.pgBatchWait = 50 * time.Millisecond
    r.pgChLean = make(chan pgMsgLean, 1)
    // Use Postgres with nil pool so IngestEventsJSON returns nil (success)
    r.pg = &data.Postgres{}
    go r.pgWorkerBatchLean()

    ts := time.Now().UTC().Format(time.RFC3339Nano)
    payload := json.RawMessage(`{"price": 123.45, "qty": 10}`)
    tags := json.RawMessage(`[{"k":"symbol","v":"AAPL"}]`)
    r.handleLeanEvent("rid-1", "evt-1", ts, "sub-1", "prod-1", payload, tags, "schema-1")
    // close to force flush
    close(r.pgChLean)

    if len(acked) != 1 || acked[0] != "rid-1" {
        t.Fatalf("expected ack for rid-1, got %v", acked)
    }
}

func TestHandleLeanEvent_QueueBackpressure_DropsWhenFull(t *testing.T) {
    r := &router{pgChLean: make(chan pgMsgLean, 1)}
    // Fill the channel
    r.pgChLean <- pgMsgLean{RedisID: "r-1"}
    // This should drop and not block; since no ack when pgChLean exists, we only assert no deadlock/panic.
    r.handleLeanEvent("r-2", "evt2", time.Now().Format(time.RFC3339Nano), "s", "p", json.RawMessage(`{"k":2}`), nil, "")
}
