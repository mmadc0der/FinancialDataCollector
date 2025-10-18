-- Immutable schema helpers and atomic subject upgrade
-- Idempotent and concurrency-safe with advisory locks

-- Ensure immutable schema by (name, version).
-- If exists: optionally verify body matches (when provided).
-- If missing: create only when create_if_missing=true.
CREATE OR REPLACE FUNCTION public.ensure_schema_immutable(
    _name TEXT,
    _version INT,
    _body JSONB,
    _create_if_missing BOOLEAN DEFAULT FALSE
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE v_schema_id UUID;
DECLARE v_existing_body JSONB;
BEGIN
    IF _name IS NULL OR _version IS NULL THEN RAISE EXCEPTION 'schema name/version required'; END IF;

    SELECT schema_id, body INTO v_schema_id, v_existing_body
    FROM public.schemas
    WHERE name=_name AND version=_version;

    IF v_schema_id IS NOT NULL THEN
        -- Immutability: if caller supplies body, it must match exactly
        IF _body IS NOT NULL AND v_existing_body IS DISTINCT FROM _body THEN
            RAISE EXCEPTION 'immutable violation: schema % v% body differs from existing', _name, _version;
        END IF;
        RETURN v_schema_id;
    END IF;

    IF NOT _create_if_missing THEN
        RAISE EXCEPTION 'schema not found and create_if_missing=false: % v%', _name, _version;
    END IF;

    INSERT INTO public.schemas(schema_id, name, version, body)
    VALUES (gen_random_uuid(), _name, _version, COALESCE(_body, '{}'::jsonb))
    RETURNING schema_id INTO v_schema_id;
    RETURN v_schema_id;
END;
$$;

-- Ensure subject row exists and update attrs per merge policy; bump last_seen_at.
CREATE OR REPLACE FUNCTION public.ensure_subject(
    _subject_key TEXT,
    _attrs JSONB DEFAULT NULL,
    _merge BOOLEAN DEFAULT TRUE
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE v_subject_id UUID;
BEGIN
    IF _subject_key IS NULL OR length(_subject_key)=0 THEN RAISE EXCEPTION 'subject_key required'; END IF;

    INSERT INTO public.subjects(subject_id, subject_key, attrs)
    VALUES (gen_random_uuid(), _subject_key, COALESCE(_attrs, '{}'::jsonb))
    ON CONFLICT (subject_key) DO NOTHING;

    SELECT subject_id INTO v_subject_id FROM public.subjects WHERE subject_key=_subject_key;

    IF _attrs IS NOT NULL THEN
        IF _merge THEN
            UPDATE public.subjects
            SET attrs = public.subjects.attrs || _attrs, last_seen_at = now()
            WHERE subject_id = v_subject_id;
        ELSE
            UPDATE public.subjects
            SET attrs = _attrs, last_seen_at = now()
            WHERE subject_id = v_subject_id;
        END IF;
    ELSE
        UPDATE public.subjects SET last_seen_at = now() WHERE subject_id = v_subject_id;
    END IF;
    RETURN v_subject_id;
END;
$$;

-- Atomically create next schema version for a name and set it as current for the subject.
-- Returns subject_id, schema_id, and assigned version.
CREATE OR REPLACE FUNCTION public.upgrade_subject_schema_auto(
    _subject_key TEXT,
    _name TEXT,
    _body JSONB,
    _attrs JSONB DEFAULT NULL,
    _merge BOOLEAN DEFAULT TRUE
) RETURNS TABLE(subject_id UUID, schema_id UUID, version INT) LANGUAGE plpgsql AS $$
DECLARE v_subject_id UUID;
DECLARE v_schema_id UUID;
DECLARE v_next_version INT;
BEGIN
    IF _name IS NULL THEN RAISE EXCEPTION 'schema name required'; END IF;
    -- Serialize per schema name to avoid version collisions
    PERFORM pg_advisory_xact_lock(hashtext(_name));

    SELECT COALESCE(MAX(version), 0) + 1 INTO v_next_version FROM public.schemas WHERE name=_name;
    INSERT INTO public.schemas(schema_id, name, version, body)
    VALUES (gen_random_uuid(), _name, v_next_version, COALESCE(_body, '{}'::jsonb))
    RETURNING schema_id INTO v_schema_id;

    v_subject_id := public.ensure_subject(_subject_key, _attrs, _merge);
    PERFORM public.set_current_subject_schema(v_subject_id, v_schema_id);

    subject_id := v_subject_id;
    schema_id := v_schema_id;
    version := v_next_version;
    RETURN;
END;
$$;


