package kernel_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	ulid "github.com/oklog/ulid/v2"
	"github.com/gorilla/websocket"
	"github.com/example/data-kernel/internal/protocol"
	"github.com/example/data-kernel/internal/kernelcfg"
	"github.com/example/data-kernel/internal/testutil"
)

func dialWS(t *testing.T, url, token string) *websocket.Conn {
	d := websocket.Dialer{}
	h := http.Header{"X-Auth-Token": []string{token}}
	c, _, err := d.Dial(url, h)
	if err != nil { t.Fatalf("dial: %v", err) }
	return c
}

func TestWS_AuthRejected(t *testing.T) {
	inst := testutil.StartKernel(t, nil)
	defer inst.Close()
	// missing token
	_, _, err := websocket.DefaultDialer.Dial(inst.URL, nil)
	if err == nil { t.Fatalf("expected unauthorized error") }
}

func TestWS_AckAndHello(t *testing.T) {
    var token string
    inst := testutil.StartKernel(t, func(cfg *kernelcfg.Config) { token = cfg.Server.AuthToken })
	defer inst.Close()
	c := dialWS(t, inst.URL, token)
	defer c.Close()
	// read optional hello
	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, msg, err := c.ReadMessage()
	if err == nil {
		var env map[string]any
		_ = json.Unmarshal(msg, &env)
	}
	// send a valid envelope and expect ack
	env := protocol.Envelope{Version: protocol.Version, Type: "data", ID: ulid.Make().String(), TS: time.Now().UnixNano(), Data: json.RawMessage(`{"x":1}`)}
	buf, _ := json.Marshal(env)
	if err := c.WriteMessage(websocket.TextMessage, buf); err != nil { t.Fatal(err) }
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err = c.ReadMessage()
	if err != nil { t.Fatalf("read ack: %v", err) }
	var ack protocol.Ack
	if err := json.Unmarshal(msg, &ack); err != nil {
		t.Fatalf("bad ack json: %v", err)
	}
	if ack.Type != "ack" || ack.LastID != env.ID { t.Fatalf("unexpected ack: %+v", ack) }
}

