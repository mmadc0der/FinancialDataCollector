-- Fresh core schema (idempotent).
-- 1) Extensions
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- 2) Schemas and producers
CREATE TABLE IF NOT EXISTS schemas (
    schema_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    version INT NOT NULL,
    body JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, version)
);
CREATE TABLE IF NOT EXISTS producers (
    producer_id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at TIMESTAMPTZ
);
-- 3) Subjects
CREATE TABLE IF NOT EXISTS subjects (
    subject_id UUID PRIMARY KEY,
    subject_key TEXT NOT NULL UNIQUE,
    attrs JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- M:N relationships
CREATE TABLE IF NOT EXISTS producer_subjects (
    producer_id UUID NOT NULL REFERENCES producers(producer_id),
    subject_id UUID NOT NULL REFERENCES subjects(subject_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (producer_id, subject_id)
);
CREATE TABLE IF NOT EXISTS subject_schemas (
    subject_id UUID NOT NULL REFERENCES subjects(subject_id),
    schema_id UUID NOT NULL REFERENCES schemas(schema_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_id, schema_id)
);
CREATE TABLE IF NOT EXISTS tags (
    tag_id BIGSERIAL PRIMARY KEY,
    key CITEXT NOT NULL CHECK (length(key) > 0),
    value CITEXT NOT NULL CHECK (length(value) > 0),
    UNIQUE (key, value)
);
-- 5) Events (partitioned), lean payload as single JSON
CREATE TABLE IF NOT EXISTS events (
    event_id UUID NOT NULL,
    partition_month DATE NOT NULL,
    producer_id UUID NOT NULL REFERENCES producers(producer_id) DEFERRABLE INITIALLY DEFERRED,
    schema_id UUID NOT NULL REFERENCES schemas(schema_id) DEFERRABLE INITIALLY DEFERRED,
    payload JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, partition_month)
) PARTITION BY LIST (partition_month);
-- 6) Event <-> Tag (partition-aligned), no FK to events for cheap drops
CREATE TABLE IF NOT EXISTS event_tags (
    event_id UUID NOT NULL,
    partition_month DATE NOT NULL,
    tag_id BIGINT NOT NULL REFERENCES tags(tag_id),
    PRIMARY KEY (event_id, partition_month, tag_id)
) PARTITION BY LIST (partition_month);
CREATE TABLE IF NOT EXISTS event_index (
    event_id UUID PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    subject_id UUID,
    partition_month DATE GENERATED ALWAYS AS (date_trunc('month', (ts AT TIME ZONE 'UTC'))::date) STORED
);
CREATE INDEX IF NOT EXISTS idx_event_index_brin_ts ON event_index USING BRIN (ts);
CREATE INDEX IF NOT EXISTS idx_event_index_subject_month ON event_index (subject_id, partition_month);
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE c.conname = 'event_index_future_ts'
        AND n.nspname = 'public'
        AND t.relname = 'event_index'
) THEN EXECUTE 'ALTER TABLE public.event_index ADD CONSTRAINT event_index_future_ts CHECK (ts <= now() + interval ''1 hour'')';
END IF;
END $$;
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE c.conname = 'event_index_past_ts'
        AND n.nspname = 'public'
        AND t.relname = 'event_index'
) THEN EXECUTE 'ALTER TABLE public.event_index ADD CONSTRAINT event_index_past_ts CHECK (ts >= now() - interval ''1 month'')';
END IF;
END $$;
-- 10) Spill table for failed ingests
CREATE TABLE IF NOT EXISTS ingest_spill (
    spill_id BIGSERIAL PRIMARY KEY,
    event_id UUID,
    ts TIMESTAMPTZ,
    subject_id UUID,
    producer_id UUID,
    schema_id UUID,
    payload JSONB,
    tags JSONB,
    error TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE c.conname = 'fk_events_event_index'
        AND n.nspname = 'public'
        AND t.relname = 'events'
) THEN EXECUTE 'ALTER TABLE public.events ADD CONSTRAINT fk_events_event_index FOREIGN KEY (event_id) REFERENCES public.event_index(event_id) NOT DEFERRABLE';
END IF;
END $$;

-- Auth tables for producer tokens and blacklist (idempotent)
-- 1) producer_tokens: issued tokens metadata
CREATE TABLE IF NOT EXISTS public.producer_tokens (
    token_id UUID PRIMARY KEY,
    producer_id UUID NOT NULL REFERENCES public.producers(producer_id),
    jti TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    notes TEXT
);

-- 2) revoked_tokens: explicit blacklist (jti)
CREATE TABLE IF NOT EXISTS public.revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason TEXT
);

-- subjects.current_schema_id and helper to set current schema while preserving history
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name   = 'subjects'
          AND column_name  = 'current_schema_id'
    ) THEN
        ALTER TABLE public.subjects
            ADD COLUMN current_schema_id UUID NULL REFERENCES public.schemas(schema_id);
    END IF;
END $$;

-- Optional index to accelerate lookups by current schema
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='idx_subjects_current_schema_id'
    ) THEN
        CREATE INDEX idx_subjects_current_schema_id ON public.subjects(current_schema_id);
    END IF;
END $$;

-- Helper to set current schema for a subject and record historical relation
CREATE OR REPLACE FUNCTION public.set_current_subject_schema(
    _subject_id UUID,
    _schema_id  UUID
) RETURNS UUID LANGUAGE plpgsql AS $$
BEGIN
    IF _subject_id IS NULL THEN RAISE EXCEPTION 'subject_id required'; END IF;
    IF _schema_id IS NULL THEN RAISE EXCEPTION 'schema_id required'; END IF;
    -- preserve history (idempotent)
    INSERT INTO public.subject_schemas(subject_id, schema_id)
    VALUES (_subject_id, _schema_id)
    ON CONFLICT (subject_id, schema_id) DO NOTHING;
    -- set current
    UPDATE public.subjects SET current_schema_id = _schema_id, last_seen_at = now()
    WHERE subject_id = _subject_id;
    RETURN _schema_id;
END;
$$;

-- Registration Security Redesign v2 - Fixed Migration (compacted)
-- Create tables and handle existing constraints properly

-- Create producer_keys table if it doesn't exist
CREATE TABLE IF NOT EXISTS public.producer_keys (
    fingerprint TEXT PRIMARY KEY,
    producer_id UUID REFERENCES public.producers(producer_id),
    pubkey TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|revoked|superseded
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    superseded_at TIMESTAMPTZ,
    superseded_by TEXT REFERENCES public.producer_keys(fingerprint),
    notes TEXT
);

-- Create producer_registrations table if it doesn't exist
CREATE TABLE IF NOT EXISTS public.producer_registrations (
    reg_id UUID PRIMARY KEY,
    fingerprint TEXT NOT NULL REFERENCES public.producer_keys(fingerprint),
    payload JSONB NOT NULL,
    sig TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|rejected|...
    reason TEXT,
    reviewed_at TIMESTAMPTZ,
    reviewer TEXT
);

-- Drop existing constraints if they exist
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_status' AND conrelid = 'public.producer_keys'::regclass) THEN
        ALTER TABLE public.producer_keys DROP CONSTRAINT check_status;
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_reg_status' AND conrelid = 'public.producer_registrations'::regclass) THEN
        ALTER TABLE public.producer_registrations DROP CONSTRAINT check_reg_status;
    END IF;
END $$;

-- Add superseded columns to producer_keys if they don't exist
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'producer_keys' AND column_name = 'superseded_at') THEN
        ALTER TABLE public.producer_keys ADD COLUMN superseded_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'producer_keys' AND column_name = 'superseded_by') THEN
        ALTER TABLE public.producer_keys ADD COLUMN superseded_by TEXT REFERENCES public.producer_keys(fingerprint);
    END IF;
END $$;

-- Make producer_id NOT NULL (clean up orphaned keys first)
DELETE FROM public.producer_keys WHERE producer_id IS NULL;
ALTER TABLE public.producer_keys ALTER COLUMN producer_id SET NOT NULL;

-- Add new constraints
ALTER TABLE public.producer_keys 
ADD CONSTRAINT check_status CHECK (status IN ('pending', 'approved', 'revoked', 'superseded'));

ALTER TABLE public.producer_registrations 
ADD CONSTRAINT check_reg_status CHECK (
    status IN (
        'pending',
        'approved',
        'rejected',
        'replay',
        'invalid_sig',
        'invalid_cert',
        'revoked',
        'superseded'
    )
);

-- Enforce DB-backed nonce uniqueness per fingerprint
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='idx_producer_registrations_fp_nonce'
) THEN
    EXECUTE 'CREATE UNIQUE INDEX idx_producer_registrations_fp_nonce ON public.producer_registrations(fingerprint, nonce)';
END IF; END $$;

-- Add unique constraint: only ONE approved key per producer at a time
-- First, handle any existing violations by superseding duplicates
WITH ranked_keys AS (
    SELECT fingerprint, producer_id, 
           ROW_NUMBER() OVER (PARTITION BY producer_id ORDER BY approved_at DESC NULLS LAST, created_at DESC) as rn
    FROM public.producer_keys 
    WHERE status = 'approved'
)
UPDATE public.producer_keys 
SET status = 'superseded', 
    superseded_at = now(),
    superseded_by = (SELECT fingerprint FROM ranked_keys rk2 WHERE rk2.producer_id = producer_keys.producer_id AND rk2.rn = 1)
FROM ranked_keys 
WHERE public.producer_keys.fingerprint = ranked_keys.fingerprint 
  AND ranked_keys.rn > 1;

-- Now add the unique constraint
CREATE UNIQUE INDEX IF NOT EXISTS idx_producer_keys_one_approved_per_producer 
ON public.producer_keys (producer_id) 
WHERE status = 'approved';

-- Function: Approve new producer key (case 1: new producer)
CREATE OR REPLACE FUNCTION public.approve_producer_key_new(
    _fingerprint TEXT,
    _name TEXT,
    _reviewer TEXT,
    _notes TEXT DEFAULT NULL
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE 
    v_producer_id UUID;
BEGIN
    -- Validate inputs
    IF _fingerprint IS NULL OR length(_fingerprint) = 0 THEN
        RAISE EXCEPTION 'fingerprint required';
    END IF;
    IF _name IS NULL OR length(_name) = 0 THEN
        RAISE EXCEPTION 'producer name required';
    END IF;
    
    -- Key must exist and be pending
    IF NOT EXISTS (SELECT 1 FROM public.producer_keys WHERE fingerprint = _fingerprint AND status = 'pending') THEN
        RAISE EXCEPTION 'unknown or non-pending fingerprint %', _fingerprint;
    END IF;
    
    -- Get the producer_id from the pending key
    SELECT producer_id INTO v_producer_id FROM public.producer_keys 
    WHERE fingerprint = _fingerprint AND status = 'pending';
    
    IF v_producer_id IS NULL THEN
        RAISE EXCEPTION 'producer not found for fingerprint %', _fingerprint;
    END IF;
    
    -- Update existing producer with approved name and notes
    UPDATE public.producers
    SET name = _name,
        description = COALESCE(_notes, description)
    WHERE producer_id = v_producer_id;
    
    -- Approve and update the key
    UPDATE public.producer_keys
    SET status = 'approved',
        approved_at = now(),
        notes = COALESCE(_notes, notes)
    WHERE fingerprint = _fingerprint;
    
    -- Update registrations
    UPDATE public.producer_registrations
    SET status = 'approved',
        reviewed_at = now(),
        reviewer = NULLIF(_reviewer, '')
    WHERE fingerprint = _fingerprint AND status = 'pending';
    
    RETURN v_producer_id;
END;
$$;

-- Function: Approve key rotation (case 2: existing producer, new key)
CREATE OR REPLACE FUNCTION public.approve_key_rotation(
    _fingerprint TEXT,
    _producer_id UUID,
    _reviewer TEXT,
    _notes TEXT DEFAULT NULL
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE 
    v_old_fingerprint TEXT;
BEGIN
    -- Validate inputs
    IF _fingerprint IS NULL OR length(_fingerprint) = 0 THEN
        RAISE EXCEPTION 'fingerprint required';
    END IF;
    IF _producer_id IS NULL THEN
        RAISE EXCEPTION 'producer_id required';
    END IF;
    
    -- Producer must exist
    IF NOT EXISTS (SELECT 1 FROM public.producers WHERE producer_id = _producer_id) THEN
        RAISE EXCEPTION 'unknown producer_id %', _producer_id;
    END IF;
    
    -- New key must exist, be pending, and belong to this producer
    IF NOT EXISTS (
        SELECT 1 FROM public.producer_keys 
        WHERE fingerprint = _fingerprint 
          AND status = 'pending' 
          AND producer_id = _producer_id
    ) THEN
        RAISE EXCEPTION 'unknown, non-pending, or mismatched fingerprint % for producer %', _fingerprint, _producer_id;
    END IF;
    
    -- Find current approved key for this producer
    SELECT fingerprint INTO v_old_fingerprint
    FROM public.producer_keys 
    WHERE producer_id = _producer_id AND status = 'approved';
    
    -- Start transaction to atomically supersede old key and approve new key
    IF v_old_fingerprint IS NOT NULL THEN
        -- Supersede old key
        UPDATE public.producer_keys
        SET status = 'superseded',
            superseded_at = now(),
            superseded_by = _fingerprint
        WHERE fingerprint = v_old_fingerprint;
    END IF;
    
    -- Approve new key
    UPDATE public.producer_keys
    SET status = 'approved',
        approved_at = now(),
        notes = COALESCE(_notes, notes)
    WHERE fingerprint = _fingerprint;
    
    -- Update registrations
    UPDATE public.producer_registrations
    SET status = 'approved',
        reviewed_at = now(),
        reviewer = NULLIF(_reviewer, '')
    WHERE fingerprint = _fingerprint AND status = 'pending';
    
    RETURN _producer_id;
END;
$$;

-- Function: Reject producer key
CREATE OR REPLACE FUNCTION public.reject_producer_key(
    _fingerprint TEXT,
    _reviewer TEXT,
    _reason TEXT
) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    -- Validate inputs
    IF _fingerprint IS NULL OR length(_fingerprint) = 0 THEN
        RAISE EXCEPTION 'fingerprint required';
    END IF;
    IF _reason IS NULL OR length(_reason) = 0 THEN
        RAISE EXCEPTION 'reason required for rejection';
    END IF;
    
    -- Key must exist
    IF NOT EXISTS (SELECT 1 FROM public.producer_keys WHERE fingerprint = _fingerprint) THEN
        RAISE EXCEPTION 'unknown fingerprint %', _fingerprint;
    END IF;
    
    -- Mark key as revoked
    UPDATE public.producer_keys
    SET status = 'revoked',
        revoked_at = now(),
        notes = COALESCE(_reason, notes)
    WHERE fingerprint = _fingerprint;
    
    -- Mark registrations as rejected
    UPDATE public.producer_registrations
    SET status = 'rejected',
        reviewed_at = now(),
        reviewer = NULLIF(_reviewer, ''),
        reason = _reason
    WHERE fingerprint = _fingerprint AND status = 'pending';
END;
$$;

-- Function: Get key status (for token exchange validation)
CREATE OR REPLACE FUNCTION public.get_key_status(_fingerprint TEXT)
RETURNS TABLE(status TEXT, producer_id UUID) LANGUAGE plpgsql AS $$
BEGIN
    RETURN QUERY
    SELECT pk.status, pk.producer_id
    FROM public.producer_keys pk
    WHERE pk.fingerprint = _fingerprint;
END;
$$;

-- Function: Register new producer + key atomically (for first-time registration)
-- Creates a new producer, inserts the key row with producer_id binding, and returns producer_id
CREATE OR REPLACE FUNCTION public.register_producer_key(
    _fingerprint TEXT,
    _pubkey TEXT,
    _producer_hint TEXT DEFAULT NULL,
    _contact TEXT DEFAULT NULL,
    _meta JSONB DEFAULT NULL
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE 
    v_producer_id UUID;
    v_producer_name TEXT;
    v_description TEXT;
BEGIN
    -- Validate inputs
    IF _fingerprint IS NULL OR length(_fingerprint) = 0 THEN
        RAISE EXCEPTION 'fingerprint required';
    END IF;
    IF _pubkey IS NULL OR length(_pubkey) = 0 THEN
        RAISE EXCEPTION 'pubkey required';
    END IF;
    
    -- Determine producer name (human-readable or auto-generated)
    v_producer_name := COALESCE(_producer_hint, '');
    IF length(v_producer_name) = 0 THEN
        -- Generate deterministic name from fingerprint
        v_producer_name := 'auto_' || substring(_fingerprint, 1, 12);
    END IF;
    
    -- Build description from contact and meta
    v_description := '';
    IF _contact IS NOT NULL AND length(_contact) > 0 THEN
        v_description := 'Contact: ' || _contact;
    END IF;
    IF _meta IS NOT NULL THEN
        IF length(v_description) > 0 THEN
            v_description := v_description || ' | Meta: ' || _meta::text;
        ELSE
            v_description := 'Meta: ' || _meta::text;
        END IF;
    END IF;
    
    -- Create or get producer
    INSERT INTO public.producers(producer_id, name, description)
    VALUES (gen_random_uuid(), v_producer_name, NULLIF(v_description, ''))
    ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name, description = NULLIF(v_description, '')
    RETURNING producer_id INTO v_producer_id;
    
    -- Insert or update producer_key row with producer binding (starts as pending)
    INSERT INTO public.producer_keys(fingerprint, producer_id, pubkey, status)
    VALUES (_fingerprint, v_producer_id, _pubkey, 'pending')
    ON CONFLICT (fingerprint) DO UPDATE 
    SET producer_id = v_producer_id, 
        pubkey = EXCLUDED.pubkey
    WHERE public.producer_keys.status NOT IN ('approved', 'revoked');
    
    RETURN v_producer_id;
END;
$$;

-- Update producer_overview view to include superseded info
CREATE OR REPLACE VIEW public.producer_overview AS
SELECT pk.fingerprint,
       pk.status,
       pk.created_at,
       pk.approved_at,
       pk.revoked_at,
       pk.superseded_at,
       pk.superseded_by,
       p.producer_id,
       p.name,
       p.description,
       p.created_at AS producer_created_at
FROM public.producer_keys pk
LEFT JOIN public.producers p ON p.producer_id = pk.producer_id;

-- Helper to atomically ensure schema (by name/version) and subject (by subject_key)
CREATE OR REPLACE FUNCTION public.ensure_schema_subject(
    _name TEXT,
    _version INT,
    _body JSONB,
    _subject_key TEXT,
    _attrs JSONB
) RETURNS TABLE(schema_id UUID, subject_id UUID) LANGUAGE plpgsql AS $$
DECLARE v_schema_id UUID;
DECLARE v_subject_id UUID;
BEGIN
    IF _name IS NULL OR _version IS NULL THEN RAISE EXCEPTION 'schema name/version required'; END IF;
    IF _subject_key IS NULL OR length(_subject_key)=0 THEN RAISE EXCEPTION 'subject_key required'; END IF;
    -- upsert schema by (name,version)
    INSERT INTO public.schemas(schema_id, name, version, body)
    VALUES (gen_random_uuid(), _name, _version, COALESCE(_body, '{}'::jsonb))
    ON CONFLICT (name, version) DO UPDATE SET body = EXCLUDED.body
    RETURNING public.schemas.schema_id INTO v_schema_id;
    -- upsert subject by subject_key
    INSERT INTO public.subjects(subject_id, subject_key, attrs)
    VALUES (gen_random_uuid(), _subject_key, COALESCE(_attrs, '{}'::jsonb))
    ON CONFLICT (subject_key) DO UPDATE SET attrs = COALESCE(EXCLUDED.attrs, subjects.attrs), last_seen_at = now()
    RETURNING public.subjects.subject_id INTO v_subject_id;
    schema_id := v_schema_id;
    subject_id := v_subject_id;
    RETURN QUERY SELECT v_schema_id, v_subject_id;
END;
$$;

-- Helper to bind producer to subject (M:N) by subject_key
CREATE OR REPLACE FUNCTION public.ensure_producer_subject(
    _producer_id UUID,
    _subject_key TEXT
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE v_subject_id UUID;
BEGIN
    IF _producer_id IS NULL THEN RAISE EXCEPTION 'producer_id required'; END IF;
    IF _subject_key IS NULL OR length(_subject_key)=0 THEN RAISE EXCEPTION 'subject_key required'; END IF;
    SELECT subject_id INTO v_subject_id FROM public.subjects WHERE subject_key=_subject_key;
    IF v_subject_id IS NULL THEN
        v_subject_id := gen_random_uuid();
        INSERT INTO public.subjects(subject_id, subject_key, attrs) VALUES (v_subject_id, _subject_key, '{}'::jsonb)
        ON CONFLICT (subject_key) DO UPDATE SET last_seen_at=now() RETURNING subject_id INTO v_subject_id;
    END IF;
    INSERT INTO public.producer_subjects(producer_id, subject_id) VALUES (_producer_id, v_subject_id)
    ON CONFLICT (producer_id, subject_id) DO NOTHING;
    RETURN v_subject_id;
END;
$$;
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE c.conname = 'fk_event_tags_index'
        AND n.nspname = 'public'
        AND t.relname = 'event_tags'
) THEN EXECUTE 'ALTER TABLE public.event_tags ADD CONSTRAINT fk_event_tags_index FOREIGN KEY (event_id) REFERENCES public.event_index(event_id) NOT DEFERRABLE';
END IF;
END $$;