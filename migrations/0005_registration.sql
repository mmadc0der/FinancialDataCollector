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

