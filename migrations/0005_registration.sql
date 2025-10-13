-- Registration and key management
CREATE TABLE IF NOT EXISTS public.producer_keys (
    fingerprint TEXT PRIMARY KEY,
    producer_id UUID NULL REFERENCES public.producers(producer_id),
    pubkey TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|revoked
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS public.producer_registrations (
    reg_id UUID PRIMARY KEY,
    fingerprint TEXT NOT NULL REFERENCES public.producer_keys(fingerprint),
    payload JSONB NOT NULL,
    sig TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|rejected|auto_issued
    reason TEXT,
    reviewed_at TIMESTAMPTZ,
    reviewer TEXT
);

-- Enforce DB-backed nonce uniqueness per fingerprint
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='idx_producer_registrations_fp_nonce'
) THEN
    EXECUTE 'CREATE UNIQUE INDEX idx_producer_registrations_fp_nonce ON public.producer_registrations(fingerprint, nonce)';
END IF; END $$;

-- Approve a producer key and optionally create a producer, binding the key to it
-- Returns the bound/created producer_id
CREATE OR REPLACE FUNCTION public.approve_producer_key(
    _fingerprint TEXT,
    _name TEXT,
    _schema_id UUID,
    _reviewer TEXT,
    _notes TEXT
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE v_producer_id UUID;
BEGIN
    IF _fingerprint IS NULL OR length(_fingerprint) = 0 THEN
        RAISE EXCEPTION 'fingerprint required';
    END IF;
    -- Key must exist and not be revoked
    IF NOT EXISTS (SELECT 1 FROM public.producer_keys WHERE fingerprint = _fingerprint) THEN
        RAISE EXCEPTION 'unknown fingerprint %', _fingerprint;
    END IF;
    IF EXISTS (SELECT 1 FROM public.producer_keys WHERE fingerprint = _fingerprint AND status = 'revoked') THEN
        RAISE EXCEPTION 'fingerprint revoked %', _fingerprint;
    END IF;
    -- Use existing producer if already bound
    SELECT producer_id INTO v_producer_id FROM public.producer_keys WHERE fingerprint = _fingerprint;
    IF v_producer_id IS NULL THEN
        IF _schema_id IS NULL THEN
            RAISE EXCEPTION 'schema_id required to create producer';
        END IF;
        IF _name IS NULL OR length(_name) = 0 THEN
            RAISE EXCEPTION 'producer name required to create producer';
        END IF;
        v_producer_id := gen_random_uuid();
        INSERT INTO public.producers(producer_id, name, description, schema_id)
        VALUES (v_producer_id, _name, COALESCE(_notes, ''), _schema_id);
    END IF;
    UPDATE public.producer_keys
    SET producer_id = v_producer_id,
        status = 'approved',
        approved_at = now(),
        notes = COALESCE(_notes, notes)
    WHERE fingerprint = _fingerprint;
    UPDATE public.producer_registrations
    SET status = 'approved',
        reviewed_at = now(),
        reviewer = NULLIF(_reviewer, '')
    WHERE fingerprint = _fingerprint AND status = 'pending';
    RETURN v_producer_id;
END;
$$;

-- Atomically gate auto-issue per hour and record token metadata
CREATE OR REPLACE FUNCTION public.try_auto_issue_and_record(
    _fingerprint TEXT,
    _jti TEXT,
    _expires_at TIMESTAMPTZ,
    _notes TEXT
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE v_producer_id UUID;
DECLARE v_window TIMESTAMPTZ;
BEGIN
    -- lock key row to avoid races
    SELECT producer_id INTO v_producer_id FROM public.producer_keys WHERE fingerprint = _fingerprint AND status='approved' AND producer_id IS NOT NULL FOR UPDATE;
    IF v_producer_id IS NULL THEN
        RETURN NULL;
    END IF;
    v_window := date_trunc('hour', now());
    -- insert rate window row; if exists, deny
    INSERT INTO public.producer_auto_issues(fingerprint, window_start) VALUES (_fingerprint, v_window) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    -- record token (idempotent on jti)
    INSERT INTO public.producer_tokens(token_id, producer_id, jti, expires_at, notes)
    VALUES (gen_random_uuid(), v_producer_id, _jti, _expires_at, COALESCE(_notes,''))
    ON CONFLICT (jti) DO NOTHING;
    -- mark latest pending regs as auto_issued
    UPDATE public.producer_registrations SET status='auto_issued', reviewed_at=now()
    WHERE fingerprint=_fingerprint AND status='pending';
    RETURN v_producer_id;
END;
$$;

-- Auto-issue rate limiting (one per hour per fingerprint)
CREATE TABLE IF NOT EXISTS public.producer_auto_issues (
    fingerprint TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (fingerprint, window_start)
);

