package kernel

import (
    "encoding/json"
    "log"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/protocol"
    "github.com/example/data-kernel/internal/sink"
)

type router struct {
	sinks *sink.NDJSONFileSink
}

func newRouter(cfg *kernelcfg.Config) (*router, error) {
	fs, err := sink.NewNDJSONFileSink(cfg.Sinks.File)
	if err != nil {
		return nil, err
	}
	return &router{sinks: fs}, nil
}

func (r *router) handle(env protocol.Envelope) {
	// For now, directly write envelopes to file sink
	if err := r.sinks.WriteJSON(env); err != nil {
		log.Printf("sink write error: %v", err)
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

