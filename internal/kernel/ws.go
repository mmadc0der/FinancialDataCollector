package kernel

import (
    "encoding/json"
    "net/http"
    "sync"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/logging"
    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/metrics"
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
            CheckOrigin: func(r *http.Request) bool {
                if len(cfg.Server.AllowedOrigins) == 0 {
                    return true
                }
                origin := r.Header.Get("Origin")
                for _, o := range cfg.Server.AllowedOrigins {
                    if o == origin {
                        return true
                    }
                }
                return false
            },
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
        if token == "" {
            // try bearer token
            const prefix = "Bearer "
            authz := r.Header.Get("Authorization")
            if len(authz) > len(prefix) && authz[:len(prefix)] == prefix {
                token = authz[len(prefix):]
            }
        }
        // constant-time compare
        if !secureCompare(token, s.cfg.Server.AuthToken) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	c, err := s.upgrader.Upgrade(w, r, nil)
    if err != nil {
        logging.Warn("ws_upgrade_error", logging.F("err", err.Error()))
		return
	}
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
    metrics.WSConnections.Inc()

	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		_ = c.Close()
        metrics.WSConnections.Dec()
	}()

	c.SetReadLimit(s.cfg.Server.MaxMessageBytes)
	c.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.Server.ReadTimeoutMs) * time.Millisecond))
	c.SetPongHandler(func(string) error {
		c.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.Server.ReadTimeoutMs) * time.Millisecond))
		return nil
	})

    // send hello/control with window size (if configured)
    if s.cfg.Server.WindowSize > 0 {
        hello := map[string]any{
            "version": protocol.Version,
            "type": "control",
            "id": "hello",
            "ts": time.Now().UnixNano(),
            "data": map[string]any{"window_size": s.cfg.Server.WindowSize},
        }
        buf, _ := json.Marshal(hello)
        _ = c.WriteMessage(websocket.TextMessage, buf)
    }

    // heartbeat: use ping frames periodically
    go func() {
        ticker := time.NewTicker(time.Duration(s.cfg.Server.ReadTimeoutMs/3) * time.Millisecond)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                _ = c.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(2*time.Second))
            }
        }
    }()

    for {
        _, msg, err := c.ReadMessage()
        if err != nil {
            logging.Warn("ws_read_error", logging.F("err", err.Error()))
			return
		}
        var env protocol.Envelope
        if err := json.Unmarshal(msg, &env); err != nil {
			_ = c.WriteMessage(websocket.TextMessage, protocol.ErrorEnvelope("bad_json", err.Error()))
			continue
		}
        if err := protocol.ValidateEnvelope(env); err != nil {
            _ = c.WriteMessage(websocket.TextMessage, protocol.ErrorEnvelope("bad_envelope", err.Error()))
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

// secureCompare does constant time string compare
func secureCompare(a, b string) bool {
    if len(a) != len(b) {
        return false
    }
    var v byte
    for i := 0; i < len(a); i++ {
        v |= a[i] ^ b[i]
    }
    return v == 0
}

