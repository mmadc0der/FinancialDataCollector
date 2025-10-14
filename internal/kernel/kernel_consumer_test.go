package kernel

import (
    "encoding/json"
    "testing"
)

func TestPrefixed(t *testing.T) {
    if prefixed("", "k") != "k" { t.Fatalf("no prefix case failed") }
    if prefixed("fdc:", "events") != "fdc:events" { t.Fatalf("prefix case failed") }
}

func TestProtocolEnvelopeAdapter(t *testing.T) {
    type lite struct{ Version string `json:"version"`; Type string `json:"type"`; ID string `json:"id"`; TS int64 `json:"ts"`; Data json.RawMessage `json:"data"` }
    l := lite{Version: "0.1.0", Type: "data", ID: "X", TS: 1, Data: json.RawMessage(`{"a":1}`)}
    e := protocolEnvelope(l)
    if e.Version != l.Version || e.Type != l.Type || e.ID != l.ID || e.TS != l.TS || string(e.Data) != string(l.Data) {
        t.Fatalf("adapter mismatch: %+v vs %+v", e, l)
    }
}


