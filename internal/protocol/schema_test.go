package protocol

import (
    "encoding/json"
    "testing"
    "time"

    "github.com/google/uuid"
)

func TestValidateEnvelope_Success(t *testing.T) {
    u, _ := uuid.NewV7()
    e := Envelope{Version: Version, Type: "data", ID: u.String(), TS: time.Now().UnixNano(), Data: json.RawMessage(`{"k":1}`)}
    if err := ValidateEnvelope(e); err != nil {
        t.Fatalf("expected valid envelope, got error: %v", err)
    }
}

func TestValidateEnvelope_Errors(t *testing.T) {
    v1, _ := uuid.NewV7(); v2, _ := uuid.NewV7(); v3, _ := uuid.NewV7()
    cases := []Envelope{
        {Version: "", Type: "data", ID: v1.String(), TS: time.Now().UnixNano()},
        {Version: Version, Type: "unknown", ID: v2.String(), TS: time.Now().UnixNano()},
        {Version: Version, Type: "data", ID: "", TS: time.Now().UnixNano()},
        {Version: Version, Type: "data", ID: v3.String(), TS: 0},
    }
    for i, e := range cases {
        if err := ValidateEnvelope(e); err == nil {
            t.Fatalf("case %d: expected error, got nil", i)
        }
    }
}

func TestCanonicalizeJSON(t *testing.T) {
    in := []byte(`{"b":2, "a":1}`)
    out := CanonicalizeJSON(in)
    // Must be valid JSON and round-trip to same structure
    var vin, vout any
    if err := json.Unmarshal(in, &vin); err != nil { t.Fatalf("invalid input json: %v", err) }
    if err := json.Unmarshal(out, &vout); err != nil { t.Fatalf("invalid output json: %v", err) }
    bin, _ := json.Marshal(vin)
    bout, _ := json.Marshal(vout)
    if string(bin) != string(bout) {
        t.Fatalf("canonicalize did not preserve structure: %s vs %s", string(bin), string(bout))
    }
}