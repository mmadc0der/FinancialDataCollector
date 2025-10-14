package protocol

import (
    "encoding/json"
    "time"

    "github.com/google/uuid"
)

const Version = "0.1.0"

type Envelope struct {
	Version string          `json:"version"`
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	TS      int64           `json:"ts"`
	Data    json.RawMessage `json:"data"`
}

type Ack struct {
	Version string `json:"version"`
	Type    string `json:"type"`
	ID      string `json:"id"`
	TS      int64  `json:"ts"`
	LastID  string `json:"last_id"`
}

func NewAck(lastID string) Ack {
	return Ack{
		Version: Version,
		Type:    "ack",
        ID:      func() string { u, _ := uuid.NewV7(); return u.String() }(),
		TS:      time.Now().UnixNano(),
		LastID:  lastID,
	}
}

func ErrorEnvelope(code, message string) []byte {
	e := map[string]any{
		"version": Version,
		"type":    "error",
        "id":      func() string { u, _ := uuid.NewV7(); return u.String() }(),
		"ts":      time.Now().UnixNano(),
		"data": map[string]string{
			"code":    code,
			"message": message,
		},
	}
	b, _ := json.Marshal(e)
	return b
}

// ValidateEnvelope performs lightweight validation of the envelope shape.
func ValidateEnvelope(e Envelope) error {
    if e.Version == "" || e.Version != Version {
        return &Err{Code: "bad_version", Message: "invalid or mismatched version"}
    }
    switch e.Type {
    case "data", "heartbeat", "control", "ack", "error":
    default:
        return &Err{Code: "bad_type", Message: "unsupported type"}
    }
    if e.ID == "" {
        return &Err{Code: "bad_id", Message: "missing id"}
    }
    if e.TS == 0 {
        return &Err{Code: "bad_ts", Message: "missing ts"}
    }
    // data may be empty for some control/ack messages
    return nil
}

// CanonicalizeJSON returns a canonical JSON encoding with stable key ordering.
// It unmarshals and re-marshals the input to enforce a deterministic encoding.
func CanonicalizeJSON(in []byte) []byte {
    var tmp any
    if json.Unmarshal(in, &tmp) != nil {
        return in
    }
    b, err := json.Marshal(tmp)
    if err != nil { return in }
    return b
}

type Err struct {
    Code    string
    Message string
}

func (e *Err) Error() string { return e.Code + ": " + e.Message }

