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
    group string
}

func NewRedis(cfg kernelcfg.RedisConfig) (*Redis, error) {
    // Use configurable timeouts for different operations
    readTimeout := time.Duration(cfg.ReadTimeoutMs) * time.Millisecond
    writeTimeout := time.Duration(cfg.WriteTimeoutMs) * time.Millisecond
    dialTimeout := time.Duration(cfg.DialTimeoutMs) * time.Millisecond

    client := redis.NewClient(&redis.Options{
        Addr: cfg.Addr,
        Username: cfg.Username,
        Password: cfg.Password,
        DB: cfg.DB,
        ReadTimeout: readTimeout,
        WriteTimeout: writeTimeout,
        DialTimeout: dialTimeout,
        // Configurable connection pooling
        PoolSize: cfg.PoolSize,
        MinIdleConns: cfg.MinIdleConns,
    })
    stream := cfg.Stream
    if cfg.KeyPrefix != "" { stream = cfg.KeyPrefix + stream }
    return &Redis{cfg: cfg, c: client, stream: stream, group: cfg.ConsumerGroup}, nil
}

func (r *Redis) XAdd(ctx context.Context, id string, payload []byte) error {
    if r.c == nil || r.stream == "" {
        return nil
    }
    xaddTimeout := time.Duration(r.cfg.XAddTimeoutMs) * time.Millisecond
    cctx, cancel := context.WithTimeout(ctx, xaddTimeout)
    defer cancel()
    return r.c.XAdd(cctx, &redis.XAddArgs{
        Stream: r.stream,
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

// Ack acknowledges processed IDs and deletes them from the stream for exact-one consumption.
func (r *Redis) Ack(ctx context.Context, ids ...string) error {
    if r.c == nil || r.stream == "" || r.group == "" || len(ids) == 0 { return nil }

    // Use pipeline for better performance with bulk operations
    pipe := r.c.Pipeline()
    pipe.XAck(ctx, r.stream, r.group, ids...)
    pipe.XTrimMaxLenApprox(ctx, r.stream, 32384, 0)
    _, err := pipe.Exec(ctx)
    return err
}

// AckStream acknowledges messages for a specific stream and trims it.
func (r *Redis) AckStream(ctx context.Context, stream string, ids ...string) error {
    if r.c == nil || stream == "" || r.group == "" || len(ids) == 0 { return nil }
    pipe := r.c.Pipeline()
    pipe.XAck(ctx, stream, r.group, ids...)
    pipe.XTrimMaxLenApprox(ctx, stream, 32384, 0)
    _, err := pipe.Exec(ctx)
    return err
}



// ToDLQ writes a payload to DLQ stream.
func (r *Redis) ToDLQ(ctx context.Context, dlqStream string, id string, payload []byte, errMsg string) error {
    if r.c == nil || dlqStream == "" { return nil }
    err := r.c.XAdd(ctx, &redis.XAddArgs{Stream: dlqStream, Values: map[string]any{"id": id, "payload": payload, "error": errMsg}}).Err()
    return err
}

// DecodeMessage extracts json payload and token from XMessage values.
func DecodeMessage(msg redis.XMessage) (string, []byte, string) {
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


// Schema cache helpers: fdc:schemas:<subject_id> -> schema_id with sliding TTL
func (r *Redis) SchemaCacheGet(ctx context.Context, subjectID string) (string, bool) {
    if r.c == nil || subjectID == "" { return "", false }
    key := r.cfg.KeyPrefix + "schemas:" + subjectID
    val, err := r.c.Get(ctx, key).Result()
    if err == nil && val != "" {
        // sliding TTL refresh (1h) - use pipeline for efficiency
        r.c.Expire(ctx, key, time.Hour)
        return val, true
    }
    return "", false
}

func (r *Redis) SchemaCacheSet(ctx context.Context, subjectID, schemaID string, ttl time.Duration) error {
    if r.c == nil || subjectID == "" || schemaID == "" { return nil }
    key := r.cfg.KeyPrefix + "schemas:" + subjectID
    if ttl <= 0 { ttl = time.Hour }
    return r.c.Set(ctx, key, schemaID, ttl).Err()
}

// SchemaCacheSetBatch sets multiple schema cache entries efficiently using pipeline.
func (r *Redis) SchemaCacheSetBatch(ctx context.Context, entries map[string]string, ttl time.Duration) error {
    if r.c == nil || len(entries) == 0 { return nil }
    if ttl <= 0 { ttl = time.Hour }

    pipe := r.c.Pipeline()
    for subjectID, schemaID := range entries {
        if subjectID != "" && schemaID != "" {
            key := r.cfg.KeyPrefix + "schemas:" + subjectID
            pipe.Set(ctx, key, schemaID, ttl)
        }
    }
    _, err := pipe.Exec(ctx)
    return err
}


