package protocol

import (
    "encoding/json"
    "time"

    ulid "github.com/oklog/ulid/v2"
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
		ID:      ulid.Make().String(),
		TS:      time.Now().UnixNano(),
		LastID:  lastID,
	}
}

func ErrorEnvelope(code, message string) []byte {
	e := map[string]any{
		"version": Version,
		"type":    "error",
		"id":      ulid.Make().String(),
		"ts":      time.Now().UnixNano(),
		"data": map[string]string{
			"code":    code,
			"message": message,
		},
	}
	b, _ := json.Marshal(e)
	return b
}

