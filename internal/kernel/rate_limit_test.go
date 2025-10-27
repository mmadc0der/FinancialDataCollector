package kernel

import (
    "context"
    "testing"
    "time"

    "github.com/example/data-kernel/internal/data"
    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/redis/go-redis/v9"
)

func TestRateLimit(t *testing.T) {
    // Skip if Redis not available
    client := redis.NewClient(&redis.Options{
        Addr: "127.0.0.1:6379",
        DB:   1, // Use different DB for tests
    })
    defer client.Close()
    
    ctx := context.Background()
    if err := client.Ping(ctx).Err(); err != nil {
        t.Skip("Redis not available for testing")
    }
    
    // Create Redis instance
    rd, err := data.NewRedis(kernelcfg.RedisConfig{
        Addr: "127.0.0.1:6379",
        DB:   1,
        KeyPrefix: "test:",
    })
    if err != nil {
        t.Fatalf("NewRedis: %v", err)
    }
    defer rd.Close()
    
    // Create test kernel with rate limiting enabled
    cfg := &kernelcfg.Config{
        Auth: kernelcfg.AuthConfig{
            RegistrationRateLimitRPM: 2, // 2 requests per minute
            RegistrationRateLimitBurst: 1, // 1 burst
        },
        Redis: kernelcfg.RedisConfig{
            KeyPrefix: "test:",
        },
    }
    
    k := &Kernel{
        cfg: cfg,
        rd: rd,
    }
    
    fingerprint := "test-fingerprint-123"
    
    // First request should be allowed
    if !k.checkRateLimit(ctx, "reg", fingerprint) {
        t.Error("First request should be allowed")
    }
    
    // Second request should be allowed (within burst)
    if !k.checkRateLimit(ctx, "reg", fingerprint) {
        t.Error("Second request should be allowed (burst)")
    }
    
    // Third request should be rate limited
    if k.checkRateLimit(ctx, "reg", fingerprint) {
        t.Error("Third request should be rate limited")
    }
    
    // Wait a bit and try again - should still be rate limited
    time.Sleep(100 * time.Millisecond)
    if k.checkRateLimit(ctx, "reg", fingerprint) {
        t.Error("Fourth request should still be rate limited")
    }
}

func TestRateLimit_ExactBoundary(t *testing.T) {
    client := redis.NewClient(&redis.Options{
        Addr: "127.0.0.1:6379",
        DB:   2,
    })
    defer client.Close()
    
    ctx := context.Background()
    if err := client.Ping(ctx).Err(); err != nil {
        t.Skip("Redis not available")
    }
    
    rd, err := data.NewRedis(kernelcfg.RedisConfig{
        Addr: "127.0.0.1:6379",
        DB:   2,
        KeyPrefix: "testboundary:",
    })
    if err != nil {
        t.Fatalf("NewRedis: %v", err)
    }
    defer rd.Close()
    
    cfg := &kernelcfg.Config{
        Auth: kernelcfg.AuthConfig{
            RegistrationRateLimitRPM: 1, // exactly 1 per minute
            RegistrationRateLimitBurst: 1,
        },
        Redis: kernelcfg.RedisConfig{KeyPrefix: "testboundary:"},
    }
    
    k := &Kernel{cfg: cfg, rd: rd}
    fp := "boundary-test"
    
    // First request (within limit)
    if !k.checkRateLimit(ctx, "reg", fp) {
        t.Error("First request should be allowed (within limit=1)")
    }
    
    // Second request (at burst boundary)
    if !k.checkRateLimit(ctx, "reg", fp) {
        t.Error("Second request should be allowed (burst=1)")
    }
    
    // Third request (over limit+burst)
    if k.checkRateLimit(ctx, "reg", fp) {
        t.Error("Third request should be rate limited (exceeded limit+burst)")
    }
}

func TestRateLimit_RedisUnavailable(t *testing.T) {
    ctx := context.Background()
    
    cfg := &kernelcfg.Config{
        Auth: kernelcfg.AuthConfig{
            RegistrationRateLimitRPM: 10,
            RegistrationRateLimitBurst: 2,
        },
        Redis: kernelcfg.RedisConfig{KeyPrefix: "test:"},
    }
    
    k := &Kernel{
        cfg: cfg,
        rd: nil, // No Redis
    }
    
    // Should deny (fail-closed) when Redis unavailable
    if k.checkRateLimit(ctx, "reg", "test-fp") {
        t.Error("Should deny (fail-closed) when Redis unavailable")
    }
}
