package kernel

import (
	"context"
	"encoding/json"
	"time"

	"github.com/example/data-kernel/internal/logging"
	"github.com/redis/go-redis/v9"
)

// Control messages are published by producers (authenticated) as envelope type=control with data:
// { "op": "ensure_schema_subject", "name":"<schema>", "version":1, "body": {..}, "subject_key":"<key>", "attrs":{..} }
// Kernel replies on redis.control_resp_stream with { "op":"ensure_schema_subject","schema_id":"...","subject_id":"..." }

type controlMsg struct {
	Op         string          `json:"op"`
	Name       string          `json:"name"`
	Version    int             `json:"version"`
	Body       json.RawMessage `json:"body"`
	SubjectKey string          `json:"subject_key"`
	Attrs      json.RawMessage `json:"attrs"`
}

func (k *Kernel) handleControl(ctx context.Context, redisID string, env protocolEnvelopeLite, raw []byte) bool {
	if k.pg == nil || k.rd == nil || k.cfg.Redis.ControlRespStream == "" { return false }
	var cm controlMsg
	if err := json.Unmarshal(env.Data, &cm); err != nil || cm.Op == "" { return false }
	switch cm.Op {
	case "ensure_schema_subject":
		schemaID, subjectID, err := k.pg.EnsureSchemaSubject(ctx, cm.Name, cm.Version, cm.Body, cm.SubjectKey, cm.Attrs)
		if err != nil { logging.Warn("control_ensure_error", logging.Err(err)); return false }
		resp := map[string]any{"op":"ensure_schema_subject","schema_id": schemaID, "subject_id": subjectID}
		b, _ := json.Marshal(resp)
		_ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.ControlRespStream), MaxLen: k.cfg.Redis.MaxLenApprox, Approx: true, Values: map[string]any{"payload": string(b), "ts": time.Now().UnixNano()}}).Err()
		return true
	default:
		return false
	}
}

type protocolEnvelopeLite struct{ Version string `json:"version"`; Type string `json:"type"`; ID string `json:"id"`; TS int64 `json:"ts"`; Data json.RawMessage `json:"data"` }


