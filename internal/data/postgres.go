package data

import (
    "context"
    "errors"
    "os"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/jackc/pgx/v5"
    "github.com/example/data-kernel/internal/metrics"
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
        _ = pg.applyMigrations(context.Background())
    }
    return pg, nil
}

func (p *Postgres) applyMigrations(ctx context.Context) error {
    if p.pool == nil {
        return errors.New("pg pool nil")
    }
    b, err := os.ReadFile("migrations/0001_init.sql")
    if err != nil {
        return err
    }
    cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
    defer cancel()
    _, err = p.pool.Exec(cctx, string(b))
    return err
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


