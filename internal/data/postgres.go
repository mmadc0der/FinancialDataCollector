package data

import (
    "context"
    "database/sql"
    "encoding/json"
    "encoding/hex"
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
    "golang.org/x/crypto/sha3"
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

// NewTestPostgres creates a Postgres instance with nil pool for unit tests.
// This bypasses ensurePool() checks and allows tests to verify batching/routing logic
// without requiring a database connection.
func NewTestPostgres() *Postgres {
	return NewFromPool(nil)
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

    // Ensure schema_migrations tracking table exists (idempotent)
    if _, err := p.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.schema_migrations (
        filename TEXT PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`); err != nil {
        return fmt.Errorf("ensure schema_migrations: %w", err)
    }

    for _, name := range names {
        path := filepath.Join(dir, name)
        b, err := os.ReadFile(path)
        if err != nil {
            return fmt.Errorf("read migration %s: %w", path, err)
        }
        sum := sha3.Sum512(b)
        checksum := hex.EncodeToString(sum[:])

        // Check if migration already applied with same checksum
        var existingChecksum string
        err = p.pool.QueryRow(ctx, `SELECT checksum FROM public.schema_migrations WHERE filename=$1`, name).Scan(&existingChecksum)
        if err == nil && existingChecksum == checksum {
            logging.Info("pg_migration_skip", logging.F("file", name))
            continue
        }
        // Apply (or re-apply) migration
        logging.Info("pg_apply_migration", logging.F("file", name))
        cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
        _, execErr := p.pool.Exec(cctx, string(b))
        cancel()
        if execErr != nil {
            return fmt.Errorf("exec migration %s: %w", path, execErr)
        }
        // Record/Update migration checksum
        if _, err := p.pool.Exec(ctx, `INSERT INTO public.schema_migrations(filename, checksum) VALUES ($1,$2)
            ON CONFLICT (filename) DO UPDATE SET checksum=EXCLUDED.checksum, applied_at=now()`, name, checksum); err != nil {
            return fmt.Errorf("record migration %s: %w", name, err)
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
    if p.pool == nil { return nil }
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
	if err := p.ensurePool(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var sid string
	// attrs may be empty; coalesce to '{}'::jsonb
	var a sql.NullString
	if len(attrs) > 0 {
		a = sql.NullString{String: string(attrs), Valid: true}
	}
	err := p.pool.QueryRow(cctx,
		`WITH up AS (
			INSERT INTO public.subjects(subject_id, subject_key, attrs)
			VALUES (gen_random_uuid(), $1, COALESCE($2::jsonb, '{}'::jsonb))
			ON CONFLICT (subject_key)
			DO UPDATE SET attrs = COALESCE($2::jsonb, public.subjects.attrs), last_seen_at = now()
			RETURNING subject_id
		) SELECT subject_id FROM up
		UNION ALL
		SELECT subject_id FROM public.subjects WHERE subject_key=$1 LIMIT 1`, subjectKey, a).Scan(&sid)
	if err != nil {
		return "", err
	}
	return sid, nil
}

// BindProducerSubject inserts producer_subjects link (idempotent)
func (p *Postgres) BindProducerSubject(ctx context.Context, producerID, subjectID string) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := p.pool.Exec(cctx, `INSERT INTO public.producer_subjects(producer_id, subject_id) VALUES ($1,$2) ON CONFLICT (producer_id, subject_id) DO NOTHING`, producerID, subjectID)
	return err
}

// Auth helpers
func (p *Postgres) InsertProducerToken(ctx context.Context, producerID, jti string, exp time.Time, notes string) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := p.pool.Exec(cctx, `INSERT INTO public.producer_tokens(token_id, producer_id, jti, expires_at, notes) VALUES (gen_random_uuid(), $1, $2, $3, $4) ON CONFLICT (jti) DO NOTHING`, producerID, jti, exp, notes)
	return err
}

// TokenExists returns (exists, producerID).
// On DB error it returns (false, "") and logs the error.
// It treats not-found as (false,"").
func (p *Postgres) TokenExists(ctx context.Context, jti string) (bool, string) {
	if err := p.ensurePool(); err != nil {
		logging.Error("pg_token_exists_no_pool", logging.F("err", err.Error()))
		return false, ""
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var producerID string
	var revokedAt *time.Time
	var expiresAt time.Time
	err := p.pool.QueryRow(cctx, `SELECT producer_id, revoked_at, expires_at FROM public.producer_tokens WHERE jti=$1`, jti).Scan(&producerID, &revokedAt, &expiresAt)
	if err != nil {
		if isNoRows(err) {
			return false, ""
		}
		logging.Error("pg_token_exists_query_error", logging.F("err", err.Error()))
		return false, ""
	}
	if revokedAt != nil {
		return false, ""
	}
	if time.Now().After(expiresAt) {
		return false, ""
	}
	return true, producerID
}

func (p *Postgres) RevokeToken(ctx context.Context, jti, reason string) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
    if _, err := p.pool.Exec(cctx, `INSERT INTO public.revoked_tokens(jti, reason) VALUES ($1,$2) ON CONFLICT (jti) DO UPDATE SET reason=EXCLUDED.reason, revoked_at=now()`, jti, reason); err != nil {
        return err
    }
    // Separate statement to avoid multi-command prepared statement issues
    if _, err := p.pool.Exec(cctx, `UPDATE public.producer_tokens SET revoked_at=now() WHERE jti=$1`, jti); err != nil {
        return err
    }
    return nil
}

// IsTokenRevoked returns true if token is revoked. If DB is unavailable we conservatively return true and log.
func (p *Postgres) IsTokenRevoked(ctx context.Context, jti string) bool {
	if err := p.ensurePool(); err != nil {
		logging.Error("pg_is_token_revoked_no_pool", logging.F("err", err.Error()))
		// conservative: treat unknown as revoked
		return true
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var exists bool
	if err := p.pool.QueryRow(cctx, `SELECT EXISTS(SELECT 1 FROM public.revoked_tokens WHERE jti=$1)`, jti).Scan(&exists); err != nil {
		logging.Error("pg_is_token_revoked_query_error", logging.F("err", err.Error()))
		// conservative
		return true
	}
	return exists
}

// Registration helpers
func (p *Postgres) UpsertProducerKey(ctx context.Context, fingerprint, pubkey string) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := p.pool.Exec(cctx,
		`INSERT INTO public.producer_keys(fingerprint, pubkey, status)
         VALUES ($1, $2, 'pending')
         ON CONFLICT (fingerprint) DO UPDATE SET pubkey = EXCLUDED.pubkey WHERE public.producer_keys.pubkey <> EXCLUDED.pubkey`,
		fingerprint, pubkey,
	)
	return err
}

func (p *Postgres) GetProducerKey(ctx context.Context, fingerprint string) (exists bool, status string, producerID *string) {
	if err := p.ensurePool(); err != nil {
		return false, "", nil
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var pid *string
	var st string
	err := p.pool.QueryRow(cctx, `SELECT status, producer_id FROM public.producer_keys WHERE fingerprint=$1`, fingerprint).Scan(&st, &pid)
	if err != nil {
		if isNoRows(err) {
			return false, "", nil
		}
		return false, "", nil
	}
	return true, st, pid
}

// CreateRegistration is deprecated - use RegisterProducerKey with audit parameters instead.
// This method is kept temporarily for backwards compatibility but will be removed.
// Deprecated: Use RegisterProducerKey with audit parameters.
func (p *Postgres) CreateRegistration(ctx context.Context, fingerprint, payload, sig, nonce, status, reason, reviewer string) error {
	// No-op stub - functionality moved to RegisterProducerKey
	return nil
}

// ApproveNewProducerKey approves a new producer key (case 1: new producer)
func (p *Postgres) ApproveNewProducerKey(ctx context.Context, fingerprint, name, reviewer, notes string) (string, error) {
	if err := p.ensurePool(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var pid string
	err := p.pool.QueryRow(cctx, `SELECT public.approve_producer_key_new($1,$2,$3,$4)`, fingerprint, name, reviewer, notes).Scan(&pid)
	if err != nil {
		return "", err
	}
	return pid, nil
}

// ApproveKeyRotation approves a key rotation for existing producer (case 2: key rotation)
func (p *Postgres) ApproveKeyRotation(ctx context.Context, fingerprint, producerID, reviewer, notes string) (string, error) {
	if err := p.ensurePool(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var pid string
	err := p.pool.QueryRow(cctx, `SELECT public.approve_key_rotation($1,$2,$3,$4)`, fingerprint, producerID, reviewer, notes).Scan(&pid)
	if err != nil {
		return "", err
	}
	return pid, nil
}

func (p *Postgres) RejectProducerKey(ctx context.Context, fingerprint, reviewer, reason string) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := p.pool.Exec(cctx, `SELECT public.reject_producer_key($1,$2,$3)`, fingerprint, reviewer, reason)
	return err
}

// GetKeyStatus returns the current status and producer_id for a fingerprint.
func (p *Postgres) GetKeyStatus(ctx context.Context, fingerprint string) (status string, producerID *string, err error) {
	if err := p.ensurePool(); err != nil {
		return "", nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var pid *string
	var st string
	err = p.pool.QueryRow(cctx, `SELECT status, producer_id FROM public.get_key_status($1)`, fingerprint).Scan(&st, &pid)
	if err != nil {
		if isNoRows(err) {
			// Fingerprint not found - expected for new registrations
			return "", nil, nil
		}
		return "", nil, err
	}
	return st, pid, nil
}

// Producer enable/disable flags
func (p *Postgres) DisableProducer(ctx context.Context, producerID string) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := p.pool.Exec(cctx, `UPDATE public.producers SET disabled_at = now() WHERE producer_id=$1`, producerID)
	return err
}

func (p *Postgres) EnableProducer(ctx context.Context, producerID string) error {
	if err := p.ensurePool(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := p.pool.Exec(cctx, `UPDATE public.producers SET disabled_at = NULL WHERE producer_id=$1`, producerID)
	return err
}

func (p *Postgres) IsProducerDisabled(ctx context.Context, producerID string) (bool, error) {
	if err := p.ensurePool(); err != nil {
		return false, err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var disabled *time.Time
	if err := p.pool.QueryRow(cctx, `SELECT disabled_at FROM public.producers WHERE producer_id=$1`, producerID).Scan(&disabled); err != nil {
		return false, err
	}
	return disabled != nil, nil
}

// EnsureProducerForFingerprint creates or finds a producer and binds the fingerprint without changing approval status.
// Returns the resolved producer_id.
func (p *Postgres) EnsureProducerForFingerprint(ctx context.Context, fingerprint, preferredName string) (string, error) {
	if err := p.ensurePool(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// First, see if the fingerprint already has a producer bound
	var existingPID *string
	err := p.pool.QueryRow(cctx, `SELECT producer_id FROM public.producer_keys WHERE fingerprint=$1`, fingerprint).Scan(&existingPID)
	if err == nil && existingPID != nil && *existingPID != "" {
		return *existingPID, nil
	}
	if err != nil && !isNoRows(err) {
		return "", err
	}

	// Create or get producer by name
	name := preferredName
	if name == "" {
		// fallback deterministic alias from fingerprint
		if len(fingerprint) > 12 {
			name = "auto_" + fingerprint[:12]
		} else {
			name = "auto_" + fingerprint
		}
	}
	var pid string
	if err := p.pool.QueryRow(cctx, `INSERT INTO public.producers(producer_id, name) VALUES (gen_random_uuid(), $1)
                                      ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING producer_id`, name).Scan(&pid); err != nil {
		return "", err
	}
	// Bind fingerprint to producer if not already bound; keep status as is (default pending on upsert)
	if _, err := p.pool.Exec(cctx, `UPDATE public.producer_keys SET producer_id=$2 WHERE fingerprint=$1 AND producer_id IS NULL`, fingerprint, pid); err != nil {
		return "", err
	}
	return pid, nil
}

// RegisterProducerKey atomically creates a producer and binds a fingerprint in a single Postgres transaction.
// Optionally creates an audit record if audit parameters are provided.
// Returns the new producer_id.
func (p *Postgres) RegisterProducerKey(ctx context.Context, fingerprint, pubkey, producerHint, contact string, meta map[string]string, auditPayload, auditSig, auditNonce, auditStatus, auditReason string) (string, error) {
	if err := p.ensurePool(); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var producerID string
	metaJSON, _ := json.Marshal(meta)
	
	// Prepare audit parameters
	var auditPayloadJSON any
	if auditPayload != "" {
		var payloadMap map[string]any
		if err := json.Unmarshal([]byte(auditPayload), &payloadMap); err == nil {
			auditPayloadJSON = payloadMap
		} else {
			auditPayloadJSON = auditPayload
		}
	}
	
	err := p.pool.QueryRow(cctx, `SELECT public.register_producer_key($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, 
		fingerprint, pubkey, producerHint, contact, metaJSON,
		auditPayloadJSON, auditSig, auditNonce, auditStatus, auditReason).Scan(&producerID)
	if err != nil {
		return "", err
	}
	return producerID, nil
}
