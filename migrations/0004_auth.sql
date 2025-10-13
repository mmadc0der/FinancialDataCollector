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
