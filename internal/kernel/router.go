package kernel

import (
    "context"
    "encoding/json"
    "log"
    "time"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/sink"
)

type router struct {
	sinks *sink.NDJSONFileSink
    pg   *data.Postgres
    rd   *data.Redis
    pgCh chan pgMsg
    rdCh chan rdMsg
}

func newRouter(cfg *kernelcfg.Config) (*router, error) {
	fs, err := sink.NewNDJSONFileSink(cfg.Sinks.File)
	if err != nil {
		return nil, err
	}
    r := &router{sinks: fs}
    if cfg.Postgres.Enabled {
        if pg, err := data.NewPostgres(cfg.Postgres); err == nil {
            r.pg = pg
            q := cfg.Postgres.QueueSize
            if q <= 0 { q = 1024 }
            r.pgCh = make(chan pgMsg, q)
            go r.pgWorker()
        } else {
            log.Printf("postgres init error: %v", err)
        }
    }
    if cfg.Redis.Enabled {
        if rd, err := data.NewRedis(cfg.Redis); err == nil {
            r.rd = rd
            q := cfg.Redis.QueueSize
            if q <= 0 { q = 2048 }
            r.rdCh = make(chan rdMsg, q)
            go r.rdWorker()
        } else {
            log.Printf("redis init error: %v", err)
        }
    }
    return r, nil
}

func (r *router) handle(env protocol.Envelope) {
	// For now, directly write envelopes to file sink
	if err := r.sinks.WriteJSON(env); err != nil {
		log.Printf("sink write error: %v", err)
	}
    // Publish to Redis stream if configured
    if r.rdCh != nil {
        b, _ := json.Marshal(env)
        select {
        case r.rdCh <- rdMsg{ID: env.ID, Payload: b}:
        default:
            // drop if queue full
        }
    }
    // Store to Postgres if configured
    if r.pgCh != nil {
        // attempt to extract minimal fields from data
        var dataObj map[string]any
        _ = json.Unmarshal(env.Data, &dataObj)
        var source, symbol string
        if s, ok := dataObj["source"].(string); ok { source = s }
        if s, ok := dataObj["symbol"].(string); ok { symbol = s }
        ts := time.Unix(0, env.TS)
        select {
        case r.pgCh <- pgMsg{ID: env.ID, Type: env.Type, Version: env.Version, TS: ts, Source: source, Symbol: symbol, Data: env.Data}:
        default:
            // drop if queue full
        }
    }
}

func (k *Kernel) routeRaw(msg []byte) {
    var env protocol.Envelope
    if err := json.Unmarshal(msg, &env); err != nil {
        return
    }
    if k.rt != nil {
        k.rt.handle(env)
    }
}

type pgMsg struct {
    ID string
    Type string
    Version string
    TS time.Time
    Source string
    Symbol string
    Data []byte
}

func (r *router) pgWorker() {
    for m := range r.pgCh {
        _ = r.pg.InsertEnvelope(context.Background(), m.ID, m.Type, m.Version, m.TS, m.Source, m.Symbol, m.Data)
    }
}

type rdMsg struct {
    ID string
    Payload []byte
}

func (r *router) rdWorker() {
    for m := range r.rdCh {
        _ = r.rd.XAdd(context.Background(), m.ID, m.Payload)
    }
}

