package protocol

import (
    "encoding/json"
    "testing"
    "time"

    ulid "github.com/oklog/ulid/v2"
)

func TestValidateEnvelope_Success(t *testing.T) {
    e := Envelope{Version: Version, Type: "data", ID: ulid.Make().String(), TS: time.Now().UnixNano(), Data: json.RawMessage(`{"k":1}`)}
    if err := ValidateEnvelope(e); err != nil {
        t.Fatalf("expected valid envelope, got error: %v", err)
    }
}

func TestValidateEnvelope_Errors(t *testing.T) {
    cases := []Envelope{
        {Version: "", Type: "data", ID: ulid.Make().String(), TS: time.Now().UnixNano()},
        {Version: Version, Type: "unknown", ID: ulid.Make().String(), TS: time.Now().UnixNano()},
        {Version: Version, Type: "data", ID: "", TS: time.Now().UnixNano()},
        {Version: Version, Type: "data", ID: ulid.Make().String(), TS: 0},
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