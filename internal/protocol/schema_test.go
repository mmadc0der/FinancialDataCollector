package protocol

import (
	"testing"
	"time"

	ulid "github.com/oklog/ulid/v2"
)

func TestValidateEnvelope_Ok(t *testing.T) {
	env := Envelope{
		Version: Version,
		Type:    "data",
		ID:      ulid.Make().String(),
		TS:      time.Now().UnixNano(),
	}
	if err := ValidateEnvelope(env); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEnvelope_BadVersion(t *testing.T) {
	env := Envelope{Version: "9.9.9", Type: "data", ID: ulid.Make().String(), TS: time.Now().UnixNano()}
	if err := ValidateEnvelope(env); err == nil {
		t.Fatalf("expected error for bad version")
	}
}

func TestNewAck(t *testing.T) {
	last := ulid.Make().String()
	ack := NewAck(last)
	if ack.Version != Version || ack.Type != "ack" || ack.LastID != last || ack.ID == "" || ack.TS == 0 {
		t.Fatalf("ack has invalid fields: %+v", ack)
	}
}

