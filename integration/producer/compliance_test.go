//go:build integration

package producer_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	ulid "github.com/oklog/ulid/v2"
	"github.com/gorilla/websocket"
	"github.com/example/data-kernel/internal/kernelcfg"
	"github.com/example/data-kernel/internal/protocol"
	"github.com/example/data-kernel/internal/testutil"
)

// This suite serves as a baseline for new producers to validate their behavior
// against the current protocol version and flow control semantics.

func TestProducer_Compliance_BasicHandshakeAndAck(t *testing.T) {
	var token string
	inst := testutil.StartKernel(t, func(cfg *kernelcfg.Config) { token = cfg.Server.AuthToken })
	defer inst.Close()

	d := websocket.Dialer{}
	h := http.Header{"X-Auth-Token": []string{token}}
	c, _, err := d.Dial(inst.URL, h)
	if err != nil { t.Fatalf("dial: %v", err) }
	defer c.Close()

	// Read optional hello
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var msg []byte
	if _, msg, err = c.ReadMessage(); err == nil {
		var env map[string]any
		_ = json.Unmarshal(msg, &env)
	}

	// Send a minimal valid data envelope
	env := protocol.Envelope{Version: protocol.Version, Type: "data", ID: ulid.Make().String(), TS: time.Now().UnixNano(), Data: json.RawMessage(`{"kind":"status","source":"compliance","symbol":"OK"}`)}
	b, _ := json.Marshal(env)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil { t.Fatal(err) }
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, msg, err = c.ReadMessage(); err != nil { t.Fatalf("ack read: %v", err) }
	var ack protocol.Ack
	if err := json.Unmarshal(msg, &ack); err != nil { t.Fatalf("ack json: %v", err) }
	if ack.LastID != env.ID { t.Fatalf("ack mismatch: %+v", ack) }
}

func TestProducer_Compliance_BadVersionRejected(t *testing.T) {
	var token string
	inst := testutil.StartKernel(t, func(cfg *kernelcfg.Config) { token = cfg.Server.AuthToken })
	defer inst.Close()

	d := websocket.Dialer{}
	h := http.Header{"X-Auth-Token": []string{token}}
	c, _, err := d.Dial(inst.URL, h)
	if err != nil { t.Fatalf("dial: %v", err) }
	defer c.Close()

	// Drain optional hello
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var msg []byte
	if _, msg, err = c.ReadMessage(); err == nil {
		var env map[string]any
		_ = json.Unmarshal(msg, &env)
	}

	bad := protocol.Envelope{Version: "9.9.9", Type: "data", ID: ulid.Make().String(), TS: time.Now().UnixNano(), Data: json.RawMessage(`{}`)}
	b, _ := json.Marshal(bad)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil { t.Fatal(err) }
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, msg, err = c.ReadMessage(); err != nil { t.Fatalf("error read: %v", err) }
	var env map[string]any
	if err := json.Unmarshal(msg, &env); err != nil { t.Fatalf("error json: %v", err) }
	if env["type"] != "error" { t.Fatalf("expected error envelope: %v", env) }
}

