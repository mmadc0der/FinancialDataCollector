-- Initial schema for storing protocol envelopes
-- Idempotent: uses IF NOT EXISTS where applicable

CREATE TABLE IF NOT EXISTS envelopes (
    msg_id TEXT PRIMARY KEY,
    msg_type TEXT NOT NULL,
    msg_version TEXT NOT NULL,
    msg_ts TIMESTAMPTZ NOT NULL,
    source TEXT,
    symbol TEXT,
    data JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_envelopes_type_ts ON envelopes (msg_type, msg_ts);
CREATE INDEX IF NOT EXISTS idx_envelopes_source_symbol_ts ON envelopes (source, symbol, msg_ts);
CREATE INDEX IF NOT EXISTS idx_envelopes_gin ON envelopes USING GIN (data);

