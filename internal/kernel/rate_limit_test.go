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
    if !k.checkRateLimit(ctx, fingerprint) {
        t.Error("First request should be allowed")
    }
    
    // Second request should be allowed (within burst)
    if !k.checkRateLimit(ctx, fingerprint) {
        t.Error("Second request should be allowed (burst)")
    }
    
    // Third request should be rate limited
    if k.checkRateLimit(ctx, fingerprint) {
        t.Error("Third request should be rate limited")
    }
    
    // Wait a bit and try again - should still be rate limited
    time.Sleep(100 * time.Millisecond)
    if k.checkRateLimit(ctx, fingerprint) {
        t.Error("Fourth request should still be rate limited")
    }
}
