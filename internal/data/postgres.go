package data

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
	"github.com/example/data-kernel/internal/logging"
	"github.com/example/data-kernel/internal/metrics"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is a thin wrapper around a pgxpool.Pool with helpers for our SQL helpers.
type Postgres struct {
	cfg  kernelcfg.PostgresConfig
	pool *pgxpool.Pool
}

// NewPostgres creates a Postgres instance and (optionally) applies migrations.
// ctx is used for pool creation and migrations so callers can control timeouts/cancellation.
func NewPostgres(ctx context.Context, cfg kernelcfg.PostgresConfig) (*Postgres, error) {
	pconf, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse pgxpool config: %w", err)
	}
	if cfg.MaxConns > 0 {
		pconf.MaxConns = int32(cfg.MaxConns)
	}
	if cfg.ConnMaxLifetimeMs > 0 {
		pconf.MaxConnLifetime = time.Duration(cfg.ConnMaxLifetimeMs) * time.Millisecond
	}

	pool, err := pgxpool.NewWithConfig(ctx, pconf)
	if err != nil {
		return nil, fmt.Errorf("new pgxpool: %w", err)
	}

	pg := &Postgres{cfg: cfg, pool: pool}

	if cfg.ApplyMigrations {
		if err := pg.applyMigrations(ctx); err != nil {
			pool.Close()
			return nil, fmt.Errorf("apply migrations: %w", err)
		}
	}

	return pg, nil
}

// NewFromPool constructs Postgres from an existing pool (useful for tests where you inject a pool).
// It does not attempt to apply migrations — the caller controls that.
func NewFromPool(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

// Close closes the internal pool.
func (p *Postgres) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

// helper: detect pgx/sql "no rows"
func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows)
}

// ensurePool returns an error when p.pool is nil. We prefer failing fast so callers/tests notice init problems.
func (p *Postgres) ensurePool() error {
	if p == nil || p.pool == nil {
		return errors.New("pg pool nil")
	}
	return nil
}

// applyMigrations reads .sql files from configured migrations directory and executes them in filename order.
// It errors if the directory cannot be read or a migration execution fails.
func (p *Postgres) applyMigrations(ctx context.Context) error {
	if err := p.ensurePool(); err != nil {
		return err
	}

	dir := "migrations"
	if p.cfg.MigrationsDir != "" {
		dir = p.cfg.MigrationsDir
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %q: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", path, err)
		}

		logging.Info("pg_apply_migration", logging.F("file", name))
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, execErr := p.pool.Exec(cctx, string(b))
		cancel()
		if execErr != nil {
			return fmt.Errorf("exec migration %s: %w", path, execErr)
		}
	}

	return nil
}

// ApplyMigrations exposes migration application for callers that want to run it explicitly.
func (p *Postgres) ApplyMigrations(ctx context.Context) error {
	return p.applyMigrations(ctx)
}

// Pool returns underlying pgx pool.
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

// IngestEventsJSON calls the database ingest function with a JSON array payload.
func (p *Postgres) IngestEventsJSON(ctx context.Context, batch any) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	b, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err = p.pool.Exec(cctx, `SELECT public.ingest_events($1::jsonb)`, b)
	if err != nil {
		metrics.PGErrorsTotal.Inc()
		return err
	}
	return nil
}

// EnsureMonthlyPartitions delegates to the helper using this instance's pool.
func (p *Postgres) EnsureMonthlyPartitions(ctx context.Context, monthsAhead int) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	return EnsureMonthlyPartitions(ctx, p.pool, monthsAhead)
}

// RefreshRoutingMaterializedViews delegates to the helper using this pool.
func (p *Postgres) RefreshRoutingMaterializedViews(ctx context.Context, concurrently bool) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	return RefreshRoutingMaterializedViews(ctx, p.pool, concurrently)
}

// EnsureSchemaSubject calls SQL helper to create or fetch schema and subject
func (p *Postgres) EnsureSchemaSubject(ctx context.Context, name string, version int, body []byte, subjectKey string, attrs []byte) (string, string, error) {
	if err := p.ensurePool(); err != nil {
		return "", "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var schemaID, subjectID string
	var bodyParam any
	if len(body) > 0 {
		bodyParam = string(body)
	} else {
		bodyParam = nil
	}
	var attrsParam any
	if len(attrs) > 0 {
		attrsParam = string(attrs)
	} else {
		attrsParam = nil
	}

	err := p.pool.QueryRow(cctx, `SELECT (t).schema_id, (t).subject_id FROM public.ensure_schema_subject($1,$2,$3::jsonb,$4,$5::jsonb) AS t`,
		name, version, bodyParam, subjectKey, attrsParam).Scan(&schemaID, &subjectID)
	if err != nil {
		return "", "", err
	}
	return schemaID, subjectID, nil
}

// EnsureSchemaImmutable resolves schema by (name,version) with immutability check and optional creation.
func (p *Postgres) EnsureSchemaImmutable(ctx context.Context, name string, version int, body []byte, createIfMissing bool) (string, error) {
	if err := p.ensurePool(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var schemaID string
	var bodyParam any
	if len(body) > 0 {
		bodyParam = string(body)
	} else {
		bodyParam = nil
	}
	err := p.pool.QueryRow(cctx, `SELECT public.ensure_schema_immutable($1,$2,$3::jsonb,$4)`, name, version, bodyParam, createIfMissing).Scan(&schemaID)
	if err != nil {
		return "", err
	}
	return schemaID, nil
}

// EnsureSubject ensures subject exists and updates attrs per merge policy.
func (p *Postgres) EnsureSubject(ctx context.Context, subjectKey string, attrs []byte, merge bool) (string, error) {
	if err := p.ensurePool(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var sid string
	err := p.pool.QueryRow(cctx, `SELECT public.ensure_subject($1,$2::jsonb,$3)`, subjectKey, string(attrs), merge).Scan(&sid)
	if err != nil {
		return "", err
	}
	return sid, nil
}

// BootstrapSubjectWithSchema: create-or-ensure subject and schema family v1; idempotent when body equals current
func (p *Postgres) BootstrapSubjectWithSchema(ctx context.Context, subjectKey, name string, body []byte, attrs []byte) (string, string, int, bool, error) {
	if err := p.ensurePool(); err != nil {
		return "", "", 0, false, err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var sid, schID string
	var ver int
	var unchanged bool
	var bodyParam any
	if len(body) > 0 {
		bodyParam = string(body)
	} else {
		bodyParam = nil
	}
	var attrsParam any
	if len(attrs) > 0 {
		attrsParam = string(attrs)
	} else {
		attrsParam = nil
	}
	err := p.pool.QueryRow(cctx, `SELECT (t).subject_id, (t).schema_id, (t).version, (t).unchanged FROM public.bootstrap_subject_with_schema($1,$2,$3::jsonb,$4::jsonb) AS t`,
		subjectKey, name, bodyParam, attrsParam).Scan(&sid, &schID, &ver, &unchanged)
	if err != nil {
		return "", "", 0, false, err
	}
	return sid, schID, ver, unchanged, nil
}

// UpgradeSubjectSchemaIncremental: deep-merge delta; +1 version if changed; idempotent otherwise
func (p *Postgres) UpgradeSubjectSchemaIncremental(ctx context.Context, subjectKey, name string, delta []byte, attrsDelta []byte) (string, string, int, bool, error) {
	if err := p.ensurePool(); err != nil {
		return "", "", 0, false, err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var sid, schID string
	var ver int
	var unchanged bool
	var deltaParam any
	if len(delta) > 0 {
		deltaParam = string(delta)
	} else {
		deltaParam = nil
	}
	var attrsParam any
	if len(attrsDelta) > 0 {
		attrsParam = string(attrsDelta)
	} else {
		attrsParam = nil
	}
	err := p.pool.QueryRow(cctx, `SELECT (t).subject_id, (t).schema_id, (t).version, (t).unchanged FROM public.upgrade_subject_schema_incremental($1,$2,$3::jsonb,$4::jsonb) AS t`,
		subjectKey, name, deltaParam, attrsParam).Scan(&sid, &schID, &ver, &unchanged)
	if err != nil {
		return "", "", 0, false, err
	}
	return sid, schID, ver, unchanged, nil
}

// UpgradeSubjectSchemaAuto atomically creates next version for schema name and sets current.
func (p *Postgres) UpgradeSubjectSchemaAuto(ctx context.Context, subjectKey, name string, body []byte, attrs []byte, merge bool) (string, string, int, error) {
	if err := p.ensurePool(); err != nil {
		return "", "", 0, err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var sid, schID string
	var ver int
	err := p.pool.QueryRow(cctx, `SELECT (t).subject_id, (t).schema_id, (t).version FROM public.upgrade_subject_schema_auto($1,$2,$3::jsonb,$4::jsonb,$5) AS t`,
		subjectKey, name, string(body), string(attrs), merge).Scan(&sid, &schID, &ver)
	if err != nil {
		return "", "", 0, err
	}
	return sid, schID, ver, nil
}

// SchemaExists checks by schema_id.
func (p *Postgres) SchemaExists(ctx context.Context, schemaID string) (bool, error) {
	if err := p.ensurePool(); err != nil {
		return false, err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var ok bool
	err := p.pool.QueryRow(cctx, `SELECT EXISTS(SELECT 1 FROM public.schemas WHERE schema_id=$1::uuid)`, schemaID).Scan(&ok)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// GetCurrentSchemaID returns subjects.current_schema_id for a given subject_id, or empty if null/missing.
func (p *Postgres) GetCurrentSchemaID(ctx context.Context, subjectID string) (string, error) {
	if err := p.ensurePool(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var sid *string
	if err := p.pool.QueryRow(cctx, `SELECT current_schema_id::text FROM public.subjects WHERE subject_id=$1`, subjectID).Scan(&sid); err != nil {
		return "", err
	}
	if sid == nil {
		return "", nil
	}
	return *sid, nil
}

// SetCurrentSubjectSchema sets subjects.current_schema_id and appends to subject_schemas history (via SQL helper).
func (p *Postgres) SetCurrentSubjectSchema(ctx context.Context, subjectID, schemaID string) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var sid string
	return p.pool.QueryRow(cctx, `SELECT public.set_current_subject_schema($1::uuid,$2::uuid)`, subjectID, schemaID).Scan(&sid)
}

// CheckProducerSubject verifies producer-subject binding exists.
func (p *Postgres) CheckProducerSubject(ctx context.Context, producerID, subjectID string) (bool, error) {
	if err := p.ensurePool(); err != nil {
		return false, err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var ok bool
	err := p.pool.QueryRow(cctx, `SELECT EXISTS(SELECT 1 FROM public.producer_subjects WHERE producer_id=$1 AND subject_id=$2)`, producerID, subjectID).Scan(&ok)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// EnsureSubjectByKey creates or updates a subject by key and returns subject_id
func (p *Postgres) EnsureSubjectByKey(ctx context.Context, subjectKey string, attrs []byte) (string, error) {
	if err := p.ensurePool(); err !
