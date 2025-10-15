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

-- View to list known producers and key statuses
CREATE OR REPLACE VIEW public.producer_overview AS
SELECT pk.fingerprint,
       pk.status,
       pk.created_at,
       pk.approved_at,
       pk.revoked_at,
       p.producer_id,
       p.name,
       p.description,
       p.created_at AS producer_created_at
FROM public.producer_keys pk
LEFT JOIN public.producers p ON p.producer_id = pk.producer_id;

CREATE TABLE IF NOT EXISTS public.producer_registrations (
    reg_id UUID PRIMARY KEY,
    fingerprint TEXT NOT NULL REFERENCES public.producer_keys(fingerprint),
    payload JSONB NOT NULL,
    sig TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|rejected
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
    _reviewer TEXT,
    _schema_id UUID DEFAULT NULL,
    _notes TEXT DEFAULT NULL
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
        IF _name IS NULL OR length(_name) = 0 THEN
            RAISE EXCEPTION 'producer name required to create producer';
        END IF;
        v_producer_id := gen_random_uuid();
        INSERT INTO public.producers(producer_id, name, description)
        VALUES (v_producer_id, _name, COALESCE(_notes, ''));
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
-- removed auto-issue helper and table; token issuance is handled via token exchange flow

