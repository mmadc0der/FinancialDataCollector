-- Postgres 15 features: compression, generated columns, materialized views, and ingest helper
-- Idempotent where possible. Keep heavy features off the hot insert path.
DO $$ BEGIN BEGIN EXECUTE 'ALTER TABLE IF EXISTS public.events SET (toast.compress = lz4)';
EXCEPTION
WHEN others THEN RAISE NOTICE 'lz4 not available, falling back to pglz';
EXECUTE 'ALTER TABLE IF EXISTS public.events SET (toast.compress = pglz)';
END;
END $$;
-- 3) Incremental statistics tables (idempotent)
CREATE TABLE IF NOT EXISTS public.stats_event_month (
    partition_month DATE PRIMARY KEY,
    event_count BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS public.stats_tag_month (
    tag_id BIGINT NOT NULL REFERENCES public.tags(tag_id),
    partition_month DATE NOT NULL,
    event_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tag_id, partition_month)
);
-- 2) Materialized views for routing/summaries
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_matviews
    WHERE schemaname = 'public'
        AND matviewname = 'subject_months_mv'
) THEN EXECUTE $mv$CREATE MATERIALIZED VIEW public.subject_months_mv AS
SELECT ei.subject_id,
    date_trunc('month', ei.ts)::date AS partition_month,
    COUNT(*) AS event_count
FROM public.event_index ei
WHERE ei.subject_id IS NOT NULL
GROUP BY ei.subject_id,
    date_trunc('month', ei.ts)::date $mv$;
EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS idx_subject_months_mv_pk ON public.subject_months_mv (subject_id, partition_month)';
END IF;
END $$;
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_matviews
    WHERE schemaname = 'public'
        AND matviewname = 'tag_months_mv'
) THEN EXECUTE $mv$CREATE MATERIALIZED VIEW public.tag_months_mv AS
SELECT et.tag_id,
    et.partition_month AS partition_month,
    COUNT(*) AS event_count
FROM public.event_tags et
GROUP BY et.tag_id,
    et.partition_month $mv$;
EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS idx_tag_months_mv_pk ON public.tag_months_mv (tag_id, partition_month)';
END IF;
END $$;
-- 4) Ingest helper: insert events + index + tags in a single round-trip
-- Input: JSONB array of events
-- Each element format:
-- {
--   "event_id": "uuid",
--   "ts": "2025-10-05T12:34:56.789Z",
--   "subject_id": "uuid" | null,
--   "producer_id": "uuid",
--   "schema_id": "uuid",
--   "payload": {...},
--   "tags": [{"key":"core.symbol","value":"AAPL"}, ...]
-- }
CREATE OR REPLACE FUNCTION ingest_events(_events JSONB) RETURNS TABLE(events_inserted BIGINT, tags_linked BIGINT) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public AS $$
DECLARE v_events BIGINT := 0;
v_tags BIGINT := 0;
v_batch_count INT := 0;
v_batch_limit INT := 20000;
m DATE;
v_min_ts TIMESTAMPTZ;
v_max_ts TIMESTAMPTZ;
BEGIN IF jsonb_typeof(_events) <> 'array' THEN RAISE EXCEPTION 'ingest_events expects a JSONB array';
END IF;
CREATE TEMP TABLE _stage_events ON COMMIT DROP AS
SELECT (e->>'event_id')::uuid AS event_id,
    (e->>'ts')::timestamptz AS ts,
    NULLIF(e->>'subject_id', '')::uuid AS subject_id,
    (e->>'producer_id')::uuid AS producer_id,
    (e->>'schema_id')::uuid AS schema_id,
    COALESCE(e->'payload', '{}'::jsonb) AS payload,
    CASE WHEN jsonb_typeof(e->'tags') = 'array' THEN e->'tags' ELSE '[]'::jsonb END AS tags
FROM jsonb_array_elements(_events) AS e;
-- Required fields present
IF EXISTS (
    SELECT 1
    FROM _stage_events
    WHERE event_id IS NULL
        OR ts IS NULL
        OR producer_id IS NULL
        OR schema_id IS NULL
) THEN RAISE EXCEPTION 'Missing required fields (event_id, ts, producer_id, schema_id)';
END IF;
-- Ensure batch uniqueness
IF (
    SELECT COUNT(*)
    FROM _stage_events
) <> (
    SELECT COUNT(DISTINCT event_id)
    FROM _stage_events
) THEN RAISE EXCEPTION 'Duplicate event_id in batch';
END IF;
-- Batch size guard (application should split very large batches)
SELECT COUNT(*) INTO v_batch_count
FROM _stage_events;
IF v_batch_count > v_batch_limit THEN RAISE EXCEPTION 'Batch too large (%) > %, split the batch or lower limit',
v_batch_count,
v_batch_limit;
END IF;
-- Batch-level ts guard (mirrors table CHECKs; cheap MIN/MAX)
SELECT MIN(ts),
    MAX(ts) INTO v_min_ts,
    v_max_ts
FROM _stage_events;
IF v_min_ts < now() - interval '1 month' THEN RAISE EXCEPTION 'Event ts older than 1 month is not allowed in standard ingest';
END IF;
IF v_max_ts > now() + interval '1 hour' THEN RAISE EXCEPTION 'Event ts newer than +1 hour is not allowed in standard ingest';
END IF;
-- Ensure no pre-existing event_id
IF EXISTS (
    SELECT 1
    FROM _stage_events s
        JOIN event_index ei ON ei.event_id = s.event_id
) THEN RAISE EXCEPTION 'Duplicate event_id already exists';
END IF;
BEGIN -- Auto-create partitions only for distinct months present in this batch
FOR m IN (
    SELECT DISTINCT date_trunc('month', ts)::date
    FROM _stage_events
) LOOP PERFORM ensure_month_partitions(m, 1);
END LOOP;
-- Canonical gate first
INSERT INTO event_index (event_id, ts, subject_id)
SELECT event_id,
    ts,
    subject_id
FROM _stage_events ON CONFLICT (event_id) DO NOTHING;
-- Insert events with LIST partitioning on partition_month
-- Capture newly inserted events and increment monthly stats
CREATE TEMP TABLE _inserted_events (
    partition_month DATE,
    event_id UUID
) ON COMMIT DROP;
WITH inserted AS (
    INSERT INTO events (
            event_id,
            partition_month,
            producer_id,
            schema_id,
            payload
        )
    SELECT event_id,
        date_trunc('month', ts)::date AS partition_month,
        producer_id,
        schema_id,
        payload
    FROM _stage_events ON CONFLICT (event_id, partition_month) DO NOTHING
    RETURNING partition_month,
        event_id
)
INSERT INTO _inserted_events
SELECT partition_month,
    event_id
FROM inserted;
-- Update monthly totals using only rows inserted in this call
INSERT INTO stats_event_month (partition_month, event_count)
SELECT partition_month,
    COUNT(*)
FROM _inserted_events
GROUP BY partition_month
ON CONFLICT (partition_month) DO UPDATE SET event_count = stats_event_month.event_count + EXCLUDED.event_count;
-- Expose count of inserted events
SELECT COUNT(*) INTO v_events FROM _inserted_events;
END;
-- Explode tags
CREATE TEMP TABLE _stage_tags ON COMMIT DROP AS
SELECT DISTINCT s.event_id,
    s.ts,
    (t->>'key') AS key,
    (t->>'value') AS value
FROM _stage_events s,
    LATERAL jsonb_array_elements(COALESCE(s.tags, '[]'::jsonb)) AS t
WHERE (t->>'key') IS NOT NULL
    AND (t->>'value') IS NOT NULL;
-- Upsert tag dictionary (case-insensitive CITEXT)
INSERT INTO tags(key, value)
SELECT DISTINCT key,
    value
FROM _stage_tags ON CONFLICT (key, value) DO NOTHING;
-- Link tags
-- Link tags and maintain incremental tag-by-month stats
CREATE TEMP TABLE _inserted_event_tags (
    partition_month DATE,
    tag_id BIGINT
) ON COMMIT DROP;
WITH inserted AS (
    INSERT INTO event_tags(event_id, partition_month, tag_id)
    SELECT st.event_id,
        date_trunc('month', st.ts)::date AS partition_month,
        tg.tag_id
    FROM _stage_tags st
        JOIN tags tg ON tg.key = st.key
        AND tg.value = st.value ON CONFLICT (event_id, partition_month, tag_id) DO NOTHING
    RETURNING partition_month,
        tag_id
)
INSERT INTO _inserted_event_tags
SELECT partition_month,
    tag_id
FROM inserted;
-- Increment stats for tags using only newly linked rows
INSERT INTO stats_tag_month (tag_id, partition_month, event_count)
SELECT tag_id,
    partition_month,
    COUNT(*)
FROM _inserted_event_tags
GROUP BY tag_id,
    partition_month
ON CONFLICT (tag_id, partition_month) DO UPDATE SET event_count = stats_tag_month.event_count + EXCLUDED.event_count;
-- Expose count of linked tags
SELECT COUNT(*) INTO v_tags FROM _inserted_event_tags;
RETURN QUERY
SELECT v_events,
    v_tags;
END;
$$;
-- Restrict EXECUTE permissions explicitly
REVOKE ALL ON FUNCTION public.ingest_events(jsonb) FROM PUBLIC;

-- Immutable schema helpers and subject upgrade (compacted from previous migration)

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

-- Ensure immutable schema by (name, version)
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
    SELECT s.schema_id, s.body INTO v_schema_id, v_existing_body FROM public.schemas s WHERE s.name=_name AND s.version=_version;
    IF v_schema_id IS NOT NULL THEN
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
    RETURNING public.schemas.schema_id INTO v_schema_id;
    RETURN v_schema_id;
END;
$$;

-- Ensure subject row exists and update attrs per merge policy; bump last_seen_at
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
            UPDATE public.subjects SET attrs = public.subjects.attrs || _attrs, last_seen_at = now() WHERE subject_id = v_subject_id;
        ELSE
            UPDATE public.subjects SET attrs = _attrs, last_seen_at = now() WHERE subject_id = v_subject_id;
        END IF;
    ELSE
        UPDATE public.subjects SET last_seen_at = now() WHERE subject_id = v_subject_id;
    END IF;
    RETURN v_subject_id;
END;
$$;

-- Bootstrap a subject with an initial schema family version (v1) if missing
-- Returns: subject_id, schema_id, version, unchanged (true if existing v1 matches provided body or body not provided)
CREATE OR REPLACE FUNCTION public.bootstrap_subject_with_schema(
    _subject_key TEXT,
    _name        TEXT,
    _body        JSONB,
    _attrs       JSONB DEFAULT NULL
) RETURNS TABLE(subject_id UUID, schema_id UUID, version INT, unchanged BOOLEAN)
LANGUAGE plpgsql AS $$
DECLARE
    v_subject_id     UUID;
    v_current_schema UUID;
    v_existing_body  JSONB;
    v_schema_id      UUID;
    v_version        INT;
BEGIN
    IF _subject_key IS NULL OR length(_subject_key)=0 THEN RAISE EXCEPTION 'subject_key required'; END IF;
    IF _name IS NULL OR length(_name)=0 THEN RAISE EXCEPTION 'schema name required'; END IF;

    -- Ensure subject exists (merge attrs) and get id
    v_subject_id := public.ensure_subject(_subject_key, _attrs, TRUE);

    -- If subject already has a current schema, return it and whether the body matches
    SELECT s.current_schema_id INTO v_current_schema FROM public.subjects s WHERE s.subject_id = v_subject_id;
    IF v_current_schema IS NOT NULL THEN
        SELECT sc.body, sc.schema_id, sc.version INTO v_existing_body, v_schema_id, v_version FROM public.schemas sc WHERE sc.schema_id = v_current_schema;
        subject_id := v_subject_id;
        schema_id  := v_schema_id;
        version    := v_version;
        unchanged  := (_body IS NULL) OR (v_existing_body IS NOT DISTINCT FROM COALESCE(_body, '{}'::jsonb));
        RETURN QUERY SELECT v_subject_id, v_schema_id, v_version, unchanged;
        RETURN;
    END IF;

    -- No current schema: pick existing v1 if present, else create v1 with provided body (or empty)
    SELECT sc.schema_id, sc.version INTO v_schema_id, v_version
    FROM public.schemas sc
    WHERE sc.name = _name
    ORDER BY sc.version ASC
    LIMIT 1;

    IF v_schema_id IS NULL THEN
        v_version := 1;
        INSERT INTO public.schemas(schema_id, name, version, body)
        VALUES (gen_random_uuid(), _name, v_version, COALESCE(_body, '{}'::jsonb))
        RETURNING public.schemas.schema_id INTO v_schema_id;
        unchanged := FALSE;
    ELSE
        SELECT body INTO v_existing_body FROM public.schemas WHERE schema_id = v_schema_id;
        unchanged := (_body IS NULL) OR (v_existing_body IS NOT DISTINCT FROM COALESCE(_body, '{}'::jsonb));
    END IF;

    -- Set as current for subject (idempotent) and return
    PERFORM public.set_current_subject_schema(v_subject_id, v_schema_id);
    subject_id := v_subject_id;
    schema_id  := v_schema_id;
    version    := v_version;
    RETURN QUERY SELECT v_subject_id, v_schema_id, v_version, unchanged;
END;
$$;

-- Atomic schema upgrade helpers
CREATE OR REPLACE FUNCTION public.upgrade_subject_schema_auto(
    _subject_key TEXT,
    _name TEXT,
    _body JSONB,
    _attrs JSONB DEFAULT NULL,
    _merge BOOLEAN DEFAULT TRUE
) RETURNS TABLE(subject_id UUID, schema_id UUID, version INT) LANGUAGE plpgsql AS $$
DECLARE v_subject_id UUID; DECLARE v_schema_id UUID; DECLARE v_next_version INT;
BEGIN
    IF _name IS NULL THEN RAISE EXCEPTION 'schema name required'; END IF;
    PERFORM pg_advisory_xact_lock(hashtext(_name));
    SELECT COALESCE(MAX(s.version), 0) + 1 INTO v_next_version FROM public.schemas s WHERE s.name=_name;
    INSERT INTO public.schemas(schema_id, name, version, body)
    VALUES (gen_random_uuid(), _name, v_next_version, COALESCE(_body, '{}'::jsonb))
    RETURNING public.schemas.schema_id INTO v_schema_id;
    v_subject_id := public.ensure_subject(_subject_key, _attrs, _merge);
    PERFORM public.set_current_subject_schema(v_subject_id, v_schema_id);
    RETURN QUERY SELECT v_subject_id, v_schema_id, v_next_version;
END;
$$;

CREATE OR REPLACE FUNCTION public.upgrade_subject_schema_incremental(
    _subject_key TEXT,
    _name TEXT,
    _delta JSONB,
    _attrs_delta JSONB DEFAULT NULL
) RETURNS TABLE(subject_id UUID, schema_id UUID, version INT, unchanged BOOLEAN) LANGUAGE plpgsql AS $$
DECLARE v_subject_id UUID; DECLARE v_current_schema UUID; DECLARE v_current_body JSONB; DECLARE v_new_body JSONB; DECLARE v_next INT; DECLARE v_schema_id UUID;
BEGIN
    IF _subject_key IS NULL OR length(_subject_key)=0 THEN RAISE EXCEPTION 'subject_key required'; END IF;
    IF _name IS NULL THEN RAISE EXCEPTION 'schema name required'; END IF;
    SELECT s.subject_id, s.current_schema_id INTO v_subject_id, v_current_schema FROM public.subjects s WHERE s.subject_key=_subject_key;
    IF v_subject_id IS NULL THEN RAISE EXCEPTION 'subject_not_found'; END IF;
    IF v_current_schema IS NULL THEN RAISE EXCEPTION 'subject_current_schema_missing'; END IF;
    IF NOT EXISTS (SELECT 1 FROM public.schemas s WHERE s.schema_id=v_current_schema AND s.name=_name) THEN
        RAISE EXCEPTION 'schema_family_not_found_for_subject';
    END IF;
    SELECT s.body INTO v_current_body FROM public.schemas s WHERE s.schema_id=v_current_schema;
    v_new_body := public.jsonb_deep_merge(v_current_body, COALESCE(_delta, '{}'::jsonb));
    IF _attrs_delta IS NOT NULL THEN
        UPDATE public.subjects SET attrs = public.jsonb_deep_merge(public.subjects.attrs, _attrs_delta), last_seen_at = now() WHERE subject_id=v_subject_id;
    ELSE
        UPDATE public.subjects SET last_seen_at = now() WHERE subject_id=v_subject_id;
    END IF;
    IF v_new_body IS NOT DISTINCT FROM v_current_body THEN
        SELECT s.version INTO v_next FROM public.schemas s WHERE s.schema_id=v_current_schema;
        subject_id := v_subject_id; schema_id := v_current_schema; version := v_next; unchanged := TRUE; RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(_name));
    SELECT COALESCE(MAX(s.version),0)+1 INTO v_next FROM public.schemas s WHERE s.name=_name;
    INSERT INTO public.schemas(schema_id, name, version, body)
    VALUES (gen_random_uuid(), _name, v_next, v_new_body)
    RETURNING public.schemas.schema_id INTO v_schema_id;
    PERFORM public.set_current_subject_schema(v_subject_id, v_schema_id);
    RETURN QUERY SELECT v_subject_id, v_schema_id, v_next, FALSE;
END; $$;
-- 6) Prevent changes to identity fields post-insert
CREATE OR REPLACE FUNCTION prevent_events_identity_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_id <> OLD.event_id
    OR NEW.partition_month <> OLD.partition_month THEN RAISE EXCEPTION 'events identity (event_id, partition_month) cannot be changed once set';
END IF;
RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION prevent_event_index_identity_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_id <> OLD.event_id
    OR NEW.ts <> OLD.ts THEN RAISE EXCEPTION 'event_index identity (event_id, ts) cannot be changed once set';
END IF;
RETURN NEW;
END;
$$;
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_trigger tr
        JOIN pg_class t ON t.oid = tr.tgrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE tr.tgname = 'trg_events_prevent_identity_change'
        AND n.nspname = 'public'
        AND t.relname = 'events'
) THEN EXECUTE 'CREATE TRIGGER trg_events_prevent_identity_change BEFORE UPDATE ON public.events FOR EACH ROW EXECUTE FUNCTION public.prevent_events_identity_change()';
END IF;
IF NOT EXISTS (
    SELECT 1
    FROM pg_trigger tr
        JOIN pg_class t ON t.oid = tr.tgrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE tr.tgname = 'trg_event_index_prevent_identity_change'
        AND n.nspname = 'public'
        AND t.relname = 'event_index'
) THEN EXECUTE 'CREATE TRIGGER trg_event_index_prevent_identity_change BEFORE UPDATE ON public.event_index FOR EACH ROW EXECUTE FUNCTION public.prevent_event_index_identity_change()';
END IF;
END $$;
-- 7) Partition automation helpers
CREATE OR REPLACE FUNCTION ensure_month_partitions(from_month DATE, months_ahead INT) RETURNS VOID LANGUAGE plpgsql
SET search_path = public AS $$
DECLARE m DATE;
part_name TEXT;
BEGIN FOR m IN
SELECT generate_series(
        date_trunc('month', from_month)::date,
        (
            date_trunc('month', from_month)::date + (interval '1 month' * (months_ahead -1))
        )::date,
        interval '1 month'
    )::date LOOP -- events partition (LIST on partition_month)
    part_name := format('events_%s', to_char(m, 'YYYY_MM'));
PERFORM pg_try_advisory_xact_lock(hashtext(part_name)::bigint);
IF NOT EXISTS (
    SELECT 1
    FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p ON p.oid = i.inhparent
        JOIN pg_namespace pn ON pn.oid = p.relnamespace
    WHERE p.relname = 'events'
        AND pn.nspname = 'public'
        AND c.relname = part_name
) THEN BEGIN EXECUTE format(
    'CREATE TABLE %I PARTITION OF public.events FOR VALUES IN (%L)',
    part_name,
    m::date
);
EXCEPTION
WHEN duplicate_table THEN NULL;
END;
END IF;
-- event_tags partition (LIST on partition_month)
part_name := format('event_tags_%s', to_char(m, 'YYYY_MM'));
PERFORM pg_try_advisory_xact_lock(hashtext(part_name)::bigint);
IF NOT EXISTS (
    SELECT 1
    FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p ON p.oid = i.inhparent
        JOIN pg_namespace pn ON pn.oid = p.relnamespace
    WHERE p.relname = 'event_tags'
        AND pn.nspname = 'public'
        AND c.relname = part_name
) THEN BEGIN EXECUTE format(
    'CREATE TABLE %I PARTITION OF public.event_tags FOR VALUES IN (%L)',
    part_name,
    m::date
);
EXCEPTION
WHEN duplicate_table THEN NULL;
END;
EXECUTE format(
    'CREATE INDEX IF NOT EXISTS idx_%s_tag ON %I (tag_id)',
    part_name,
    part_name
);
EXECUTE format(
    'CREATE INDEX IF NOT EXISTS idx_%s_event ON %I (event_id)',
    part_name,
    part_name
);
END IF;
END LOOP;
END;
$$;
-- 3) Security roles and grants
DO $$ BEGIN 
REVOKE INSERT, UPDATE, DELETE ON events, event_tags, event_index FROM PUBLIC;
IF EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'fdc-kernel'
) THEN 
    -- Grant minimal DML needed by kernel for ingest pipeline
    GRANT INSERT, SELECT ON public.event_index TO "fdc-kernel";
    GRANT INSERT ON public.events TO "fdc-kernel";
    GRANT INSERT ON public.event_tags TO "fdc-kernel";
    GRANT SELECT, INSERT ON public.tags TO "fdc-kernel";
    GRANT INSERT, UPDATE ON public.stats_event_month TO "fdc-kernel";
    GRANT INSERT, UPDATE ON public.stats_tag_month TO "fdc-kernel";
    GRANT EXECUTE ON FUNCTION public.ingest_events(jsonb) TO "fdc-kernel";
END IF;
END $$;