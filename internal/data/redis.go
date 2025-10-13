package data

import (
    "context"
    "encoding/json"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/redis/go-redis/v9"
)

type Redis struct {
    cfg kernelcfg.RedisConfig
    c   *redis.Client
    stream string
    maxLenApprox int64
    group string
}

func NewRedis(cfg kernelcfg.RedisConfig) (*Redis, error) {
    if !cfg.Enabled {
        return &Redis{cfg: cfg}, nil
    }
    client := redis.NewClient(&redis.Options{
        Addr: cfg.Addr,
        Username: cfg.Username,
        Password: cfg.Password,
        DB: cfg.DB,
        ReadTimeout: 3 * time.Second,
        WriteTimeout: 3 * time.Second,
        DialTimeout: 3 * time.Second,
    })
    stream := cfg.Stream
    if cfg.KeyPrefix != "" { stream = cfg.KeyPrefix + stream }
    return &Redis{cfg: cfg, c: client, stream: stream, maxLenApprox: cfg.MaxLenApprox, group: cfg.ConsumerGroup}, nil
}

func (r *Redis) XAdd(ctx context.Context, id string, payload []byte) error {
    if r.c == nil || r.stream == "" {
        return nil
    }
    cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    return r.c.XAdd(cctx, &redis.XAddArgs{
        Stream: r.stream,
        MaxLen: r.maxLenApprox,
        Approx: true,
        Values: map[string]any{"id": id, "payload": payload},
    }).Err()
}

func (r *Redis) Close() error {
    if r.c != nil {
        return r.c.Close()
    }
    return nil
}

// C exposes underlying client for advanced operations.
func (r *Redis) C() *redis.Client { return r.c }

// XAddArgs is alias to avoid importing redis in kernel
type XAddArgs = redis.XAddArgs

// EnsureGroup creates the consumer group if not exists.
func (r *Redis) EnsureGroup(ctx context.Context) error {
    if r.c == nil || r.stream == "" || r.group == "" { return nil }
    // Create group at end ($); MKSTREAM to auto-create stream
    return r.c.XGroupCreateMkStream(ctx, r.stream, r.group, "$").Err()
}

// ReadBatch reads a batch from the stream as part of the consumer group.
// Returns entries grouped by stream key.
func (r *Redis) ReadBatch(ctx context.Context, consumer string, count int, block time.Duration) ([]redis.XStream, error) {
    if r.c == nil || r.stream == "" || r.group == "" { return nil, nil }
    return r.c.XReadGroup(ctx, &redis.XReadGroupArgs{
        Group:    r.group,
        Consumer: consumer,
        Streams:  []string{r.stream, ">"},
        Count:    int64(count),
        Block:    block,
        NoAck:    false,
    }).Result()
}

// Ack acknowledges processed IDs.
func (r *Redis) Ack(ctx context.Context, ids ...string) error {
    if r.c == nil || r.stream == "" || r.group == "" || len(ids) == 0 { return nil }
    return r.c.XAck(ctx, r.stream, r.group, ids...).Err()
}

// ToDLQ writes a payload to DLQ stream.
func (r *Redis) ToDLQ(ctx context.Context, dlqStream string, id string, payload []byte, errMsg string) error {
    if r.c == nil || dlqStream == "" { return nil }
    return r.c.XAdd(ctx, &redis.XAddArgs{Stream: dlqStream, MaxLen: r.maxLenApprox, Approx: true, Values: map[string]any{"id": id, "payload": payload, "error": errMsg}}).Err()
}

// DecodeEnvelope extracts json payload from XMessage values.
func DecodeEnvelope(msg redis.XMessage) (string, []byte, string) {
    var id string
    if v, ok := msg.Values["id"].(string); ok { id = v }
    if id == "" { id = msg.ID }
    var payload []byte
    switch v := msg.Values["payload"].(type) {
    case string:
        payload = []byte(v)
    case []byte:
        payload = v
    default:
        if v != nil {
            if b, err := json.Marshal(v); err == nil { payload = b }
        }
    }
    var token string
    if t, ok := msg.Values["token"].(string); ok { token = t }
    return id, payload, token
}


