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
