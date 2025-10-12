package data

import (
    "context"

    "github.com/jackc/pgx/v5/pgxpool"
)

// RefreshRoutingMaterializedViews refreshes subject_months_mv and tag_months_mv.
// If concurrently is true, uses CONCURRENTLY.
func RefreshRoutingMaterializedViews(ctx context.Context, pool *pgxpool.Pool, concurrently bool) error {
    if pool == nil { return nil }
    if concurrently {
        if _, err := pool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY subject_months_mv"); err != nil { return err }
        if _, err := pool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY tag_months_mv"); err != nil { return err }
        return nil
    }
    if _, err := pool.Exec(ctx, "REFRESH MATERIALIZED VIEW subject_months_mv"); err != nil { return err }
    if _, err := pool.Exec(ctx, "REFRESH MATERIALIZED VIEW tag_months_mv"); err != nil { return err }
    return nil
}


