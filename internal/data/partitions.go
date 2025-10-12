package data

import (
    "context"
    "fmt"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

// EnsureMonthlyPartitions creates monthly partitions for events and event_tags for the
// current month and N months ahead. Safe to run multiple times.
func EnsureMonthlyPartitions(ctx context.Context, pool *pgxpool.Pool, monthsAhead int) error {
    if pool == nil { return nil }
    now := time.Now().UTC()
    start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
    for i := 0; i <= monthsAhead; i++ {
        from := start.AddDate(0, i, 0)
        to := start.AddDate(0, i+1, 0)
        if err := createMonthPartition(ctx, pool, "events", from, to); err != nil { return err }
        if err := createMonthPartition(ctx, pool, "event_tags", from, to); err != nil { return err }
    }
    return nil
}

func createMonthPartition(ctx context.Context, pool *pgxpool.Pool, parent string, from, to time.Time) error {
    pName := fmt.Sprintf("%s_%04d_%02d", parent, from.Year(), int(from.Month()))
    sql := fmt.Sprintf(
        "CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
        pName, parent, from.Format("2006-01-02"), to.Format("2006-01-02"),
    )
    if _, err := pool.Exec(ctx, sql); err != nil { return err }
    // Minimal per-partition indexes
    if parent == "events" {
        _, _ = pool.Exec(ctx, fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_brin_ts ON %s USING BRIN (ts)", pName, pName))
    } else if parent == "event_tags" {
        _, _ = pool.Exec(ctx, fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_tag ON %s (tag_id)", pName, pName))
        _, _ = pool.Exec(ctx, fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_event_ts ON %s (event_id, ts)", pName, pName))
        _, _ = pool.Exec(ctx, fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_brin_ts ON %s USING BRIN (ts)", pName, pName))
    }
    return nil
}


