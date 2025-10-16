-- Registration Security Redesign v2
-- Complete registration system with superseded status, single active key per producer, key rotation tracking

-- Registration and key management tables
CREATE TABLE IF NOT EXISTS public.producer_keys (
    fingerprint TEXT PRIMARY KEY,
    producer_id UUID NOT NULL REFERENCES public.producers(producer_id),
    pubkey TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|revoked|superseded
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    superseded_at TIMESTAMPTZ,
    superseded_by TEXT REFERENCES public.producer_keys(fingerprint),
    notes TEXT
);

-- Add constraints for status values
ALTER TABLE public.producer_keys 
ADD CONSTRAINT check_status CHECK (status IN ('pending', 'approved', 'revoked', 'superseded'));

-- Add unique constraint: only ONE approved key per producer at a time
CREATE UNIQUE INDEX IF NOT EXISTS idx_producer_keys_one_approved_per_producer 
ON public.producer_keys (producer_id) 
WHERE status = 'approved';

-- Registration tracking table
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

-- Add constraint for registration status values
ALTER TABLE public.producer_registrations 
ADD CONSTRAINT check_reg_status CHECK (status IN ('pending', 'approved', 'rejected'));

-- Enforce DB-backed nonce uniqueness per fingerprint
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='idx_producer_registrations_fp_nonce'
) THEN
    EXECUTE 'CREATE UNIQUE INDEX idx_producer_registrations_fp_nonce ON public.producer_registrations(fingerprint, nonce)';
END IF; END $$;

-- View to list known producers and key statuses
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
    
    -- Create new producer
    v_producer_id := gen_random_uuid();
    INSERT INTO public.producers(producer_id, name, description)
    VALUES (v_producer_id, _name, COALESCE(_notes, ''));
    
    -- Approve and bind the key
    UPDATE public.producer_keys
    SET producer_id = v_producer_id,
        status = 'approved',
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
