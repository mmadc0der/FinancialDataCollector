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
    INSERT INTO public.schemas(schema_id, name, version, body) AS sc
    VALUES (gen_random_uuid(), _name, _version, COALESCE(_body, '{}'::jsonb))
    ON CONFLICT (name, version) DO UPDATE SET body = EXCLUDED.body
    RETURNING sc.schema_id INTO v_schema_id;
    -- upsert subject by subject_key
    INSERT INTO public.subjects(subject_id, subject_key, attrs) AS s
    VALUES (gen_random_uuid(), _subject_key, COALESCE(_attrs, '{}'::jsonb))
    ON CONFLICT (subject_key) DO UPDATE SET attrs = COALESCE(EXCLUDED.attrs, subjects.attrs), last_seen_at = now()
    RETURNING s.subject_id INTO v_subject_id;
    schema_id := v_schema_id;
    subject_id := v_subject_id;
    RETURN;
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