-- Immutable schema helpers and atomic subject upgrade
-- Idempotent and concurrency-safe with advisory locks

-- Deep-merge two JSONB values (objects only; arrays replaced; scalars overridden)
CREATE OR REPLACE FUNCTION public.jsonb_deep_merge(a JSONB, b JSONB)
RETURNS JSONB LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE k TEXT; v JSONB; result JSONB := COALESCE(a, '{}'::jsonb);
BEGIN
    IF b IS NULL THEN RETURN result; END IF;
    IF jsonb_typeof(result) <> 'object' OR jsonb_typeof(b) <> 'object' THEN
        RETURN COALESCE(b, result);
    END IF;
    FOR k, v IN SELECT key, value FROM jsonb_each(b) LOOP
        IF jsonb_typeof(v) = 'object' AND jsonb_typeof(result->k) = 'object' THEN
            result := result || jsonb_build_object(k, public.jsonb_deep_merge(result->k, v));
        ELSE
            result := result || jsonb_build_object(k, v);
        END IF;
    END LOOP;
    RETURN result;
END; $$;

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

    SELECT s.schema_id, s.body INTO v_schema_id, v_existing_body
    FROM public.schemas s
    WHERE s.name=_name AND s.version=_version;

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

    SELECT COALESCE(MAX(s.version), 0) + 1 INTO v_next_version FROM public.schemas s WHERE s.name=_name;
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

-- Bootstrap: ensure subject and schema family v1 exist; idempotent when body equals current
-- Returns: subject_id, schema_id, version, unchanged
CREATE OR REPLACE FUNCTION public.bootstrap_subject_with_schema(
    _subject_key TEXT,
    _name TEXT,
    _body JSONB,
    _attrs JSONB DEFAULT NULL
) RETURNS TABLE(subject_id UUID, schema_id UUID, version INT, unchanged BOOLEAN) LANGUAGE plpgsql AS $$
DECLARE v_subject_id UUID; v_schema_id UUID; v_latest INT; v_latest_body JSONB;
BEGIN
    IF _subject_key IS NULL OR length(_subject_key)=0 THEN RAISE EXCEPTION 'subject_key required' USING ERRCODE='P0001'; END IF;
    IF _name IS NULL THEN RAISE EXCEPTION 'schema name required' USING ERRCODE='P0001'; END IF;
    PERFORM pg_advisory_xact_lock(hashtext(_name));
    WITH latest_schema AS (
        SELECT s.version, s.body FROM public.schemas s WHERE s.name=_name ORDER BY s.version DESC LIMIT 1
    )
    SELECT ls.version, ls.body INTO v_latest, v_latest_body FROM latest_schema ls;
    IF v_latest IS NULL THEN
        -- create v1
        v_latest := 1;
        INSERT INTO public.schemas(schema_id, name, version, body)
        VALUES (gen_random_uuid(), _name, v_latest, COALESCE(_body, '{}'::jsonb))
        RETURNING schema_id INTO v_schema_id;
        v_subject_id := public.ensure_subject(_subject_key, _attrs, TRUE);
        PERFORM public.set_current_subject_schema(v_subject_id, v_schema_id);
        subject_id := v_subject_id; schema_id := v_schema_id; version := v_latest; unchanged := FALSE; RETURN;
    END IF;
    -- family exists; idempotent only when requested body equals current latest
    IF v_latest_body IS NOT DISTINCT FROM COALESCE(_body, '{}'::jsonb) THEN
        SELECT s.schema_id INTO v_schema_id FROM public.schemas s WHERE s.name=_name AND s.version=v_latest;
        v_subject_id := public.ensure_subject(_subject_key, _attrs, TRUE);
        PERFORM public.set_current_subject_schema(v_subject_id, v_schema_id);
        subject_id := v_subject_id; schema_id := v_schema_id; version := v_latest; unchanged := TRUE; RETURN;
    END IF;
    RAISE EXCEPTION 'schema_family_conflict: latest body differs' USING ERRCODE='P0001';
END; $$;

-- Upgrade incremental: deep-merge delta into current; +1 version if changed; attrs delta merged
-- Returns: subject_id, schema_id, version, unchanged
CREATE OR REPLACE FUNCTION public.upgrade_subject_schema_incremental(
    _subject_key TEXT,
    _name TEXT,
    _delta JSONB,
    _attrs_delta JSONB DEFAULT NULL
) RETURNS TABLE(subject_id UUID, schema_id UUID, version INT, unchanged BOOLEAN) LANGUAGE plpgsql AS $$
DECLARE v_subject_id UUID; v_current_schema UUID; v_current_body JSONB; v_new_body JSONB; v_next INT; v_schema_id UUID;
BEGIN
    IF _subject_key IS NULL OR length(_subject_key)=0 THEN RAISE EXCEPTION 'subject_key required' USING ERRCODE='P0001'; END IF;
    IF _name IS NULL THEN RAISE EXCEPTION 'schema name required' USING ERRCODE='P0001'; END IF;
    SELECT s.subject_id, s.current_schema_id INTO v_subject_id, v_current_schema FROM public.subjects s WHERE s.subject_key=_subject_key;
    IF v_subject_id IS NULL THEN RAISE EXCEPTION 'subject_not_found' USING ERRCODE='P0001'; END IF;
    IF v_current_schema IS NULL THEN RAISE EXCEPTION 'subject_current_schema_missing' USING ERRCODE='P0001'; END IF;
    -- verify current schema belongs to family
    IF NOT EXISTS (SELECT 1 FROM public.schemas s WHERE s.schema_id=v_current_schema AND s.name=_name) THEN
        RAISE EXCEPTION 'schema_family_not_found_for_subject' USING ERRCODE='P0001';
    END IF;
    SELECT s.body INTO v_current_body FROM public.schemas s WHERE s.schema_id=v_current_schema;
    v_new_body := public.jsonb_deep_merge(v_current_body, COALESCE(_delta, '{}'::jsonb));
    -- merge attrs
    IF _attrs_delta IS NOT NULL THEN
        UPDATE public.subjects SET attrs = public.jsonb_deep_merge(public.subjects.attrs, _attrs_delta), last_seen_at = now() WHERE subject_id=v_subject_id;
    ELSE
        UPDATE public.subjects SET last_seen_at = now() WHERE subject_id=v_subject_id;
    END IF;
    IF v_new_body IS NOT DISTINCT FROM v_current_body THEN
        -- unchanged
        SELECT s.name, s.version INTO _name, v_next FROM public.schemas s WHERE s.schema_id=v_current_schema; -- v_next receives current version
        subject_id := v_subject_id; schema_id := v_current_schema; version := v_next; unchanged := TRUE; RETURN;
    END IF;
    -- create next version atomically
    PERFORM pg_advisory_xact_lock(hashtext(_name));
    SELECT COALESCE(MAX(s.version),0)+1 INTO v_next FROM public.schemas s WHERE s.name=_name;
    INSERT INTO public.schemas(schema_id, name, version, body)
    VALUES (gen_random_uuid(), _name, v_next, v_new_body)
    RETURNING schema_id INTO v_schema_id;
    PERFORM public.set_current_subject_schema(v_subject_id, v_schema_id);
    subject_id := v_subject_id; schema_id := v_schema_id; version := v_next; unchanged := FALSE; RETURN;
END; $$;


