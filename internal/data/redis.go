package data

import (
    "context"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/redis/go-redis/v9"
)

type Redis struct {
    cfg kernelcfg.RedisConfig
    c   *redis.Client
    stream string
    maxLenApprox int64
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
    return &Redis{cfg: cfg, c: client, stream: cfg.Stream, maxLenApprox: cfg.MaxLenApprox}, nil
}

func (r *Redis) XAdd(ctx context.Context, id string, payload []byte) error {
    if r.c == nil || r.stream == "" {
        return nil
    }
    cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    return r.c.XAdd(cctx, &redis.XAddArgs{
        Stream: r.stream,
        MaxLenApprox: r.maxLenApprox,
        Values: map[string]any{"id": id, "payload": payload},
    }).Err()
}

func (r *Redis) Close() error {
    if r.c != nil {
        return r.c.Close()
    }
    return nil
}


