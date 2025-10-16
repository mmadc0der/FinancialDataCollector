-- Registration Security Redesign v2 - Fixed Migration
-- Handle existing constraints properly

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
ADD CONSTRAINT check_reg_status CHECK (status IN ('pending', 'approved', 'rejected'));

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
