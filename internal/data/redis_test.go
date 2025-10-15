package data

import (
    "testing"

    "github.com/redis/go-redis/v9"
)

func TestDecodeMessage(t *testing.T) {
    msg := redis.XMessage{ID: "1-0", Values: map[string]any{"id":"custom-id","payload":"{\"x\":1}", "token": "tok"}}
    id, payload, token := DecodeMessage(msg)
    if id != "custom-id" { t.Fatalf("id mismatch: %s", id) }
    if string(payload) != "{\"x\":1}" { t.Fatalf("payload mismatch: %s", string(payload)) }
    if token != "tok" { t.Fatalf("token mismatch: %s", token) }

    msg2 := redis.XMessage{ID: "2-0", Values: map[string]any{"payload": []byte("{\"y\":2}")}}
    id2, payload2, token2 := DecodeMessage(msg2)
    if id2 != "2-0" { t.Fatalf("fallback id mismatch: %s", id2) }
    if string(payload2) != "{\"y\":2}" { t.Fatalf("payload mismatch: %s", string(payload2)) }
    if token2 != "" { t.Fatalf("expected empty token: %s", token2) }
}
