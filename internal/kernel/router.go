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
        } else {
            log.Printf("postgres init error: %v", err)
        }
    }
    if cfg.Redis.Enabled {
        if rd, err := data.NewRedis(cfg.Redis); err == nil {
            r.rd = rd
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
    if r.rd != nil {
        b, _ := json.Marshal(env)
        _ = r.rd.XAdd(context.Background(), env.ID, b)
    }
    // Store to Postgres if configured
    if r.pg != nil {
        // attempt to extract minimal fields from data
        var dataObj map[string]any
        _ = json.Unmarshal(env.Data, &dataObj)
        var source, symbol string
        if s, ok := dataObj["source"].(string); ok { source = s }
        if s, ok := dataObj["symbol"].(string); ok { symbol = s }
        ts := time.Unix(0, env.TS)
        _ = r.pg.InsertEnvelope(context.Background(), env.ID, env.Type, env.Version, ts, source, symbol, env.Data)
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

