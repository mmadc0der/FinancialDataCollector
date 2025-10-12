package data

import (
    "context"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

// EnsureMonthlyPartitions delegates to the database helper that creates LIST partitions.
func EnsureMonthlyPartitions(ctx context.Context, pool *pgxpool.Pool, monthsAhead int) error {
    if pool == nil { return nil }
    now := time.Now().UTC()
    start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
    _, err := pool.Exec(ctx, `SELECT public.ensure_month_partitions($1::date, $2::int)`, start, monthsAhead)
    return err
}


