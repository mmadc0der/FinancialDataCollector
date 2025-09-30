package data

import (
    "context"
    "errors"
    "os"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/jackc/pgx/v5/pgxpool"
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

func (p *Postgres) Close() {
    if p.pool != nil {
        p.pool.Close()
    }
}


