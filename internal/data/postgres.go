package data

import (
    "context"
    "errors"
    "encoding/json"
    "database/sql"
    "os"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/jackc/pgx/v5/pgxpool"
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
    // 0004 (auth)
    if b, err := os.ReadFile("migrations/0004_auth_and_subjects.sql"); err == nil {
        logging.Info("pg_apply_migration", logging.F("file", "0004_auth_and_subjects.sql"))
        cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        if _, e := p.pool.Exec(cctx, string(b)); e != nil { return e }
    }
    // 0005 (registration)
    if b, err := os.ReadFile("migrations/0005_registration.sql"); err == nil {
        logging.Info("pg_apply_migration", logging.F("file", "0005_registration.sql"))
        cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        if _, e := p.pool.Exec(cctx, string(b)); e != nil { return e }
    }
    // 0006 (subjects.current_schema_id)
    if b, err := os.ReadFile("migrations/0006_subject_current_schema.sql"); err == nil {
        logging.Info("pg_apply_migration", logging.F("file", "0006_subject_current_schema.sql"))
        cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        if _, e := p.pool.Exec(cctx, string(b)); e != nil { return e }
    }
    // 0007 (immutable schema helpers and atomic upgrade)
    if b, err := os.ReadFile("migrations/0007_subject_schema_ops.sql"); err == nil {
        logging.Info("pg_apply_migration", logging.F("file", "0007_subject_schema_ops.sql"))
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

// Envelope-based APIs removed (no envelope support)

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

// EnsureSchemaSubject calls SQL helper to create or fetch schema and subject
func (p *Postgres) EnsureSchemaSubject(ctx context.Context, name string, version int, body []byte, subjectKey string, attrs []byte) (string, string, error) {
    if p.pool == nil { return "", "", nil }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    var schemaID, subjectID string
    var bodyParam any
    if len(body) > 0 { bodyParam = string(body) } else { bodyParam = nil }
    var attrsParam any
    if len(attrs) > 0 { attrsParam = string(attrs) } else { attrsParam = nil }
    err := p.pool.QueryRow(cctx, `SELECT (t).schema_id, (t).subject_id FROM public.ensure_schema_subject($1,$2,$3::jsonb,$4,$5::jsonb) AS t`, name, version, bodyParam, subjectKey, attrsParam).Scan(&schemaID, &subjectID)
    if err != nil { return "", "", err }
    return schemaID, subjectID, nil
}

// EnsureSchemaImmutable resolves schema by (name,version) with immutability check and optional creation.
func (p *Postgres) EnsureSchemaImmutable(ctx context.Context, name string, version int, body []byte, createIfMissing bool) (string, error) {
    if p.pool == nil { return "", nil }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    var schemaID string
    var bodyParam any
    if len(body) > 0 { bodyParam = string(body) } else { bodyParam = nil }
    err := p.pool.QueryRow(cctx, `SELECT public.ensure_schema_immutable($1,$2,$3::jsonb,$4)`, name, version, bodyParam, createIfMissing).Scan(&schemaID)
    if err != nil { return "", err }
    return schemaID, nil
}

// EnsureSubject ensures subject exists and updates attrs per merge policy.
func (p *Postgres) EnsureSubject(ctx context.Context, subjectKey string, attrs []byte, merge bool) (string, error) {
    if p.pool == nil { return "", nil }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    var sid string
    err := p.pool.QueryRow(cctx, `SELECT public.ensure_subject($1,$2::jsonb,$3)`, subjectKey, string(attrs), merge).Scan(&sid)
    if err != nil { return "", err }
    return sid, nil
}

// UpgradeSubjectSchemaAuto atomically creates next version for schema name and sets current.
func (p *Postgres) UpgradeSubjectSchemaAuto(ctx context.Context, subjectKey, name string, body []byte, attrs []byte, merge bool) (string, string, int, error) {
    if p.pool == nil { return "", "", 0, nil }
    cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    var sid, schID string
    var ver int
    err := p.pool.QueryRow(cctx, `SELECT (t).subject_id, (t).schema_id, (t).version FROM public.upgrade_subject_schema_auto($1,$2,$3::jsonb,$4::jsonb,$5) AS t`, subjectKey, name, string(body), string(attrs), merge).Scan(&sid, &schID, &ver)
    if err != nil { return "", "", 0, err }
    return sid, schID, ver, nil
}

// SchemaExists checks by schema_id.
func (p *Postgres) SchemaExists(ctx context.Context, schemaID string) (bool, error) {
    if p.pool == nil { return false, nil }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    var ok bool
    err := p.pool.QueryRow(cctx, `SELECT EXISTS(SELECT 1 FROM public.schemas WHERE schema_id=$1::uuid)`, schemaID).Scan(&ok)
    if err != nil { return false, err }
    return ok, nil
}

// GetCurrentSchemaID returns subjects.current_schema_id for a given subject_id, or empty if null/missing.
func (p *Postgres) GetCurrentSchemaID(ctx context.Context, subjectID string) (string, error) {
    if p.pool == nil { return "", nil }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    var sid *string
    if err := p.pool.QueryRow(cctx, `SELECT current_schema_id::text FROM public.subjects WHERE subject_id=$1`, subjectID).Scan(&sid); err != nil {
        return "", err
    }
    if sid == nil { return "", nil }
    return *sid, nil
}

// SetCurrentSubjectSchema sets subjects.current_schema_id and appends to subject_schemas history (via SQL helper).
func (p *Postgres) SetCurrentSubjectSchema(ctx context.Context, subjectID, schemaID string) error {
    if p.pool == nil { return nil }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    var sid string
    return p.pool.QueryRow(cctx, `SELECT public.set_current_subject_schema($1::uuid,$2::uuid)`, subjectID, schemaID).Scan(&sid)
}

// CheckProducerSubject verifies producer-subject binding exists.
func (p *Postgres) CheckProducerSubject(ctx context.Context, producerID, subjectID string) (bool, error) {
    if p.pool == nil { return false, nil }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    var ok bool
    err := p.pool.QueryRow(cctx, `SELECT EXISTS(SELECT 1 FROM public.producer_subjects WHERE producer_id=$1 AND subject_id=$2)`, producerID, subjectID).Scan(&ok)
    if err != nil { return false, err }
    return ok, nil
}

// EnsureSubjectByKey creates or updates a subject by key and returns subject_id
func (p *Postgres) EnsureSubjectByKey(ctx context.Context, subjectKey string, attrs []byte) (string, error) {
    if p.pool == nil { return "", nil }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    var sid string
    // attrs may be empty; coalesce to '{}'::jsonb
    var a sql.NullString
    if len(attrs) > 0 { a = sql.NullString{String: string(attrs), Valid: true} }
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
    if err != nil { return "", err }
    return sid, nil
}

// BindProducerSubject inserts producer_subjects link (idempotent)
func (p *Postgres) BindProducerSubject(ctx context.Context, producerID, subjectID string) error {
    if p.pool == nil { return nil }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    _, err := p.pool.Exec(cctx, `INSERT INTO public.producer_subjects(producer_id, subject_id) VALUES ($1,$2) ON CONFLICT (producer_id, subject_id) DO NOTHING`, producerID, subjectID)
    return err
}

// Auth helpers
func (p *Postgres) InsertProducerToken(ctx context.Context, producerID, jti string, exp time.Time, notes string) error {
    if p.pool == nil { return nil }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    _, err := p.pool.Exec(cctx, `INSERT INTO public.producer_tokens(token_id, producer_id, jti, expires_at, notes) VALUES (gen_random_uuid(), $1, $2, $3, $4) ON CONFLICT (jti) DO NOTHING`, producerID, jti, exp, notes)
    return err
}

func (p *Postgres) TokenExists(ctx context.Context, jti string) (bool, string) {
    if p.pool == nil { return false, "" }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    var producerID string
    var revokedAt *time.Time
    var expiresAt time.Time
    err := p.pool.QueryRow(cctx, `SELECT producer_id, revoked_at, expires_at FROM public.producer_tokens WHERE jti=$1`, jti).Scan(&producerID, &revokedAt, &expiresAt)
    if err != nil { return false, "" }
    if revokedAt != nil { return false, "" }
    if time.Now().After(expiresAt) { return false, "" }
    return true, producerID
}

func (p *Postgres) RevokeToken(ctx context.Context, jti, reason string) error {
    if p.pool == nil { return nil }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    _, err := p.pool.Exec(cctx, `INSERT INTO public.revoked_tokens(jti, reason) VALUES ($1,$2) ON CONFLICT (jti) DO UPDATE SET reason=EXCLUDED.reason, revoked_at=now(); UPDATE public.producer_tokens SET revoked_at=now() WHERE jti=$1`, jti, reason)
    return err
}

func (p *Postgres) IsTokenRevoked(ctx context.Context, jti string) bool {
    if p.pool == nil { return true }
    cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    var exists bool
    _ = p.pool.QueryRow(cctx, `SELECT EXISTS(SELECT 1 FROM public.revoked_tokens WHERE jti=$1)`, jti).Scan(&exists)
    return exists
}

// Registration helpers
func (p *Postgres) UpsertProducerKey(ctx context.Context, fingerprint, pubkey string) error {
    if p.pool == nil { return nil }
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
    if p.pool == nil { return false, "", nil }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    var pid *string
    var st string
    err := p.pool.QueryRow(cctx, `SELECT status, producer_id FROM public.producer_keys WHERE fingerprint=$1`, fingerprint).Scan(&st, &pid)
    if err != nil { return false, "", nil }
    return true, st, pid
}

func (p *Postgres) CreateRegistration(ctx context.Context, fingerprint, payload, sig, nonce, status, reason, reviewer string) error {
    if p.pool == nil { return nil }
    cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    _, err := p.pool.Exec(cctx,
        `INSERT INTO public.producer_registrations(reg_id, fingerprint, payload, sig, nonce, status, reason, reviewed_at, reviewer)
         VALUES (gen_random_uuid(), $1, $2::jsonb, $3, $4, $5, NULLIF($6,''), CASE WHEN $7<>'' THEN now() ELSE NULL END, NULLIF($7,''))`,
        fingerprint, payload, sig, nonce, status, reason, reviewer,
    )
    return err
}

// Removed: TryAutoIssueAndRecord (auto-issue is not used in registration flow)

// ApproveNewProducerKey approves a new producer key (case 1: new producer)
func (p *Postgres) ApproveNewProducerKey(ctx context.Context, fingerprint, name, reviewer, notes string) (string, error) {
    if p.pool == nil { return "", nil }
    cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    var pid string
    err := p.pool.QueryRow(cctx, `SELECT public.approve_producer_key_new($1,$2,$3,$4)`, fingerprint, name, reviewer, notes).Scan(&pid)
    if err != nil { return "", err }
    return pid, nil
}

// ApproveKeyRotation approves a key rotation for existing producer (case 2: key rotation)
func (p *Postgres) ApproveKeyRotation(ctx context.Context, fingerprint, producerID, reviewer, notes string) (string, error) {
    if p.pool == nil { return "", nil }
    cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    var pid string
    err := p.pool.QueryRow(cctx, `SELECT public.approve_key_rotation($1,$2,$3,$4)`, fingerprint, producerID, reviewer, notes).Scan(&pid)
    if err != nil { return "", err }
    return pid, nil
}

// RejectProducerKey rejects a producer key registration
func (p *Postgres) RejectProducerKey(ctx context.Context, fingerprint, reviewer, reason string) error {
    if p.pool == nil { return nil }
    cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    _, err := p.pool.Exec(cctx, `SELECT public.reject_producer_key($1,$2,$3)`, fingerprint, reviewer, reason)
    return err
}

// GetKeyStatus returns the current status and producer_id for a fingerprint
func (p *Postgres) GetKeyStatus(ctx context.Context, fingerprint string) (status string, producerID *string, err error) {
    if p.pool == nil { return "", nil, nil }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    var pid *string
    var st string
    err = p.pool.QueryRow(cctx, `SELECT status, producer_id FROM public.get_key_status($1)`, fingerprint).Scan(&st, &pid)
    if err != nil {
        if err == sql.ErrNoRows {
            // Fingerprint not found - this is expected for new registrations
            return "", nil, nil
        }
        return "", nil, err
    }
    return st, pid, nil
}

// Producer enable/disable flags
func (p *Postgres) DisableProducer(ctx context.Context, producerID string) error {
    if p.pool == nil { return nil }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    _, err := p.pool.Exec(cctx, `UPDATE public.producers SET disabled_at = now() WHERE producer_id=$1`, producerID)
    return err
}

func (p *Postgres) EnableProducer(ctx context.Context, producerID string) error {
    if p.pool == nil { return nil }
    cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    _, err := p.pool.Exec(cctx, `UPDATE public.producers SET disabled_at = NULL WHERE producer_id=$1`, producerID)
    return err
}

func (p *Postgres) IsProducerDisabled(ctx context.Context, producerID string) (bool, error) {
    if p.pool == nil { return false, nil }
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
    if p.pool == nil { return "", nil }
    cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    // First, see if the fingerprint already has a producer bound
    var existingPID *string
    if err := p.pool.QueryRow(cctx, `SELECT producer_id FROM public.producer_keys WHERE fingerprint=$1`, fingerprint).Scan(&existingPID); err == nil && existingPID != nil && *existingPID != "" {
        return *existingPID, nil
    }
    // Create or get producer by name
    name := preferredName
    if name == "" {
        // fallback deterministic alias from fingerprint
        if len(fingerprint) > 12 { name = "auto_" + fingerprint[:12] } else { name = "auto_" + fingerprint }
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
// Returns the new producer_id.
func (p *Postgres) RegisterProducerKey(ctx context.Context, fingerprint, pubkey, producerHint, contact string, meta map[string]string) (string, error) {
    if p.pool == nil { return "", nil }
    cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    var producerID string
    metaJSON, _ := json.Marshal(meta)
    err := p.pool.QueryRow(cctx, `SELECT public.register_producer_key($1, $2, $3, $4, $5)`, fingerprint, pubkey, producerHint, contact, metaJSON).Scan(&producerID)
    if err != nil { return "", err }
    return producerID, nil
}


