//go:build integration

package kernel_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	ulid "github.com/oklog/ulid/v2"
	"github.com/gorilla/websocket"
	"github.com/example/data-kernel/internal/kernelcfg"
	"github.com/example/data-kernel/internal/protocol"
	"github.com/example/data-kernel/internal/testutil"
)

func TestIntegration_KernelWS_FileOutput(t *testing.T) {
	var token string
	var outDir string
	inst := testutil.StartKernel(t, func(cfg *kernelcfg.Config) {
		outDir = cfg.Sinks.File.Directory
		token = cfg.Server.AuthToken
	})
	defer inst.Close()
	// connect
	d := websocket.Dialer{}
	h := http.Header{"X-Auth-Token": []string{token}}
	c, _, err := d.Dial(inst.URL, h)
	if err != nil { t.Fatalf("dial: %v", err) }
	defer c.Close()
	// drain optional hello
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, msg, err := c.ReadMessage(); err == nil {
		var env map[string]any
		_ = json.Unmarshal(msg, &env)
	}
	// send envelope
	env := protocol.Envelope{Version: protocol.Version, Type: "data", ID: ulid.Make().String(), TS: time.Now().UnixNano(), Data: json.RawMessage(`{"kind":"status","source":"test","symbol":"X"}`)}
	b, _ := json.Marshal(env)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil { t.Fatal(err) }
	// expect ack
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := c.ReadMessage()
	if err != nil { t.Fatalf("ack read: %v", err) }
	var ack protocol.Ack
	if err := json.Unmarshal(msg, &ack); err != nil { t.Fatalf("ack json: %v", err) }
	if ack.LastID != env.ID { t.Fatalf("ack mismatch: %+v", ack) }
	// wait and verify file contains the envelope id
	time.Sleep(200 * time.Millisecond)
	ents, _ := os.ReadDir(outDir)
	if len(ents) == 0 { t.Fatalf("no sink files") }
	path := filepath.Join(outDir, ents[0].Name())
	f, err := os.Open(path)
	if err != nil { t.Fatal(err) }
	defer f.Close()
	s := bufio.NewScanner(f)
	found := false
	for s.Scan() {
		if len(s.Bytes()) == 0 { continue }
		var got protocol.Envelope
		_ = json.Unmarshal(s.Bytes(), &got)
		if got.ID == env.ID { found = true; break }
	}
	if !found { t.Fatalf("did not find envelope id in file: %s", path) }
}

