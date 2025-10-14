package data

import (
    "context"
    "testing"
)

func TestTagCache_GetOrCreate_CacheHitMiss(t *testing.T) {
    c := NewTagCache(nil)
    // With nil pool, GetOrCreate should error on miss
    if _, err := c.GetOrCreate(context.Background(), "k", "v"); err == nil {
        t.Fatalf("expected error when pool is nil on miss")
    }
    // Manually seed cache and ensure hit path works without pool
    c.mu.Lock()
    c.cache[cacheKey("k","v")] = 42
    c.mu.Unlock()
    id, err := c.GetOrCreate(context.Background(), "k", "v")
    if err != nil || id != 42 {
        t.Fatalf("expected cached id 42, got %d, err=%v", id, err)
    }
}


