package protocol

import "testing"

func TestCanonicalizeJSON(t *testing.T) {
    in := []byte(`{"b":2, "a":1}`)
    out := CanonicalizeJSON(in)
    if len(out) == 0 { t.Fatalf("expected non-empty output") }
}