package protocol

import "encoding/json"

// CanonicalizeJSON returns a canonical JSON encoding with stable key ordering.
func CanonicalizeJSON(in []byte) []byte {
    var tmp any
    if json.Unmarshal(in, &tmp) != nil { return in }
    b, err := json.Marshal(tmp)
    if err != nil { return in }
    return b
}

type Err struct { Code string; Message string }
func (e *Err) Error() string { return e.Code + ": " + e.Message }

