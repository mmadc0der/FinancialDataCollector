package data

import (
    "context"
    "errors"
    "encoding/json"
    "os"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/jackc/pgx/v5"
    "github.com/example/data-kernel/internal/metrics"
    "github.com/example/data-kernel/internal/logging"
)

type Postgres struct {
    cfg  kernelcfg.PostgresConfig
    pool *pgxpool.Pool
}

func NewPostgres(cfg kernelcfg.PostgresConfig) (*Postgres, error) {
    if !cfg.Enabled {
        return &Postgres{cfg: cfg}, nil
    }
    pconf, err := pgxpool.ParseConfig(cfg.DSN)
    if err != nil {
        return nil, err
    }
    if cfg.MaxConns > 0 {
        pconf.MaxConns = int32(cfg.MaxConns)
    }
    if cfg.ConnMaxLifetimeMs > 0 {
        pconf.MaxConnLifetime = time.Duration(cfg.ConnMaxLifetimeMs) * time.Millisecond
    }
    pool, err := pgxpool.NewWithConfig(context.Background(), pconf)
    if err != nil {
        return nil, err
    }
    pg := &Postgres{cfg: cfg, pool: pool}
    if cfg.ApplyMigrations {
        if err := pg.applyMigrations(context.Background()); err != nil {
            logging.Error("pg_apply_migrations_error", logging.Err(err))
        }
    }
    return pg, nil
}

func (p *Postgres) applyMigrations(ctx context.Context) error {
    if p.pool == nil {
        return errors.New("pg pool nil")
    }
    // 0001
    if b, err := os.ReadFile("migrations/0001_init.sql"); err == nil {
        logging.Info("pg_apply_migration", logging.F("file", "0001_init.sql"))
        cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        if _, e := p.pool.Exec(cctx, string(b)); e != nil { return e }
    } else {
        logging.Warn("pg_migration_missing", logging.F("file", "0001_init.sql"))
    }
    // 0002 (db features)
    if b, err := os.ReadFile("migrations/0002_db_features.sql"); err == nil {
        logging.Info("pg_apply_migration", logging.F("file", "0002_db_features.sql"))
        cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        if _, e := p.pool.Exec(cctx, string(b)); e != nil { return e }
    }
    // 0003 (developer views)
    if b, err := os.ReadFile("migrations/0003_dev_views.sql"); err == nil {
        logging.Info("pg_apply_migration", logging.F("file", "0003_dev_views.sql"))
        cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        if _, e := p.pool.Exec(cctx, string(b)); e != nil { return e }
    }
    return nil
}

// ApplyMigrations runs the SQL migration files in order. Safe to call multiple times.
func (p *Postgres) ApplyMigrations(ctx context.Context) error {
    return p.applyMigrations(ctx)
}

// IngestEventsJSON calls the database ingest function with a JSON array payload.
func (p *Postgres) IngestEventsJSON(ctx context.Context, batch any) error {
    if p.pool == nil { return nil }
    b, err := json.Marshal(batch)
    if err != nil { return err }
    cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
    defer cancel()
    _, err = p.pool.Exec(cctx, `SELECT public.ingest_events($1::jsonb)`, b)
    if err != nil { metrics.PGErrorsTotal.Inc(); return err }
    return nil
}

func (p *Postgres) InsertEnvelope(ctx context.Context, id, typ, version string, ts time.Time, source, symbol string, data []byte) error {
    if p.pool == nil {
        return nil
    }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    _, err := p.pool.Exec(cctx,
        `INSERT INTO envelopes (msg_id, msg_type, msg_version, msg_ts, source, symbol, data)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (msg_id) DO NOTHING`,
        id, typ, version, ts, source, symbol, data,
    )
    return err
}

// InsertEnvelopesBatch inserts multiple rows efficiently using CopyFrom.
func (p *Postgres) InsertEnvelopesBatch(ctx context.Context, rows []EnvelopeRow) error {
    if p.pool == nil || len(rows) == 0 { return nil }
    cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    conn, err := p.pool.Acquire(cctx)
    if err != nil { return err }
    defer conn.Release()
    input := make([][]any, 0, len(rows))
    for _, r := range rows {
        input = append(input, []any{r.ID, r.Type, r.Version, r.TS, r.Source, r.Symbol, r.Data})
    }
    _, err = conn.Conn().CopyFrom(cctx, pgx.Identifier{"envelopes"}, []string{"msg_id","msg_type","msg_version","msg_ts","source","symbol","data"}, pgx.CopyFromRows(input))
    if err != nil { metrics.PGErrorsTotal.Inc(); return err }
    metrics.PGPersistTotal.Add(float64(len(rows)))
    return nil
}

type EnvelopeRow struct {
    ID string
    Type string
    Version string
    TS time.Time
    Source string
    Symbol string
    Data []byte
}

func (p *Postgres) Close() {
    if p.pool != nil {
        p.pool.Close()
    }
}

// Pool exposes the underlying pgx pool for helper components.
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

// EnsureMonthlyPartitions delegates to the helper using this instance's pool.
func (p *Postgres) EnsureMonthlyPartitions(ctx context.Context, monthsAhead int) error {
    return EnsureMonthlyPartitions(ctx, p.pool, monthsAhead)
}

// RefreshRoutingMaterializedViews delegates to the helper using this pool.
func (p *Postgres) RefreshRoutingMaterializedViews(ctx context.Context, concurrently bool) error {
    return RefreshRoutingMaterializedViews(ctx, p.pool, concurrently)
}


