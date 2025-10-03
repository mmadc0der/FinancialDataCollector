-- Performance enhancements and notes on partitioning
-- Safe to run multiple times (IF NOT EXISTS guards)

-- 1) Add a direct index on msg_ts for time-range scans
CREATE INDEX IF NOT EXISTS idx_envelopes_ts ON envelopes (msg_ts);

-- 2) Optional: if JSON searches are rare, consider dropping the GIN index to
-- improve insert performance. Commented out by default; enable if desired.
-- DROP INDEX IF EXISTS idx_envelopes_gin;

-- 3) Partitioning note (not applied automatically):
-- Declarative partitioning requires unique constraints to include the
-- partition key. Our current unique key is (msg_id) only. To adopt
-- partitioning by time, we would need to change the unique key to
-- (msg_id, msg_ts) and adjust application upserts accordingly.
-- For now, we keep a single table with supportive indexes.


