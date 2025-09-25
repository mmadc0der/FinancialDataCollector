package kernel

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
	"github.com/example/data-kernel/internal/protocol"
	"github.com/gorilla/websocket"
)

type wsServer struct {
    upgrader websocket.Upgrader
    cfg     *kernelcfg.Config
    mu      sync.Mutex
    conns   map[*websocket.Conn]struct{}
    onMessage func([]byte)
}

func newWSServer(cfg *kernelcfg.Config, onMessage func([]byte)) *wsServer {
    return &wsServer{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
        cfg:   cfg,
        conns: map[*websocket.Conn]struct{}{},
        onMessage: onMessage,
	}
}

func (s *wsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ws" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// simple token auth via header
	if s.cfg.Server.AuthToken != "" {
		token := r.Header.Get("X-Auth-Token")
		if token != s.cfg.Server.AuthToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	c, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade error: %v", err)
		return
	}
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		_ = c.Close()
	}()

	c.SetReadLimit(s.cfg.Server.MaxMessageBytes)
	c.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.Server.ReadTimeoutMs) * time.Millisecond))
	c.SetPongHandler(func(string) error {
		c.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.Server.ReadTimeoutMs) * time.Millisecond))
		return nil
	})

	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			log.Printf("ws read error: %v", err)
			return
		}
        var env protocol.Envelope
		if err := json.Unmarshal(msg, &env); err != nil {
			_ = c.WriteMessage(websocket.TextMessage, protocol.ErrorEnvelope("bad_json", err.Error()))
			continue
		}
		// Basic echo ack for now
		ack := protocol.NewAck(env.ID)
		buf, _ := json.Marshal(ack)
		_ = c.WriteMessage(websocket.TextMessage, buf)
        if s.onMessage != nil {
            s.onMessage(msg)
        }
	}
}

