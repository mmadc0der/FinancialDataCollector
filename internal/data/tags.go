package data

import (
    "context"
    "fmt"
    "sync"

    "github.com/jackc/pgx/v5/pgxpool"
)

// TagCache resolves (key,value) to tag_id with an in-memory cache and DB upsert.
type TagCache struct {
    pool  *pgxpool.Pool
    mu    sync.RWMutex
    cache map[string]int64
}

func NewTagCache(pool *pgxpool.Pool) *TagCache {
    return &TagCache{pool: pool, cache: make(map[string]int64)}
}

func cacheKey(key, value string) string {
    return key + "\x00" + value
}

// GetOrCreate returns the tag_id for (key,value), creating it if necessary.
func (c *TagCache) GetOrCreate(ctx context.Context, key, value string) (int64, error) {
    k := cacheKey(key, value)
    c.mu.RLock()
    if id, ok := c.cache[k]; ok {
        c.mu.RUnlock()
        return id, nil
    }
    c.mu.RUnlock()
    if c.pool == nil { return 0, fmt.Errorf("pg pool nil") }
    // Single round-trip UPSERT+SELECT pattern
    var id int64
    err := c.pool.QueryRow(ctx, `
WITH s AS (
    SELECT tag_id FROM tags WHERE key = $1 AND value = $2
), i AS (
    INSERT INTO tags(key, value)
    SELECT $1, $2
    WHERE NOT EXISTS (SELECT 1 FROM s)
    ON CONFLICT (key, value) DO NOTHING
    RETURNING tag_id
)
SELECT tag_id FROM i
UNION ALL
SELECT tag_id FROM s
LIMIT 1;
`, key, value).Scan(&id)
    if err != nil { return 0, err }
    c.mu.Lock()
    c.cache[k] = id
    c.mu.Unlock()
    return id, nil
}


