# Cold Storage Index Principles

This document captures future-proofing principles for scaling `event_index` while keeping `events` partitions droppable and payloads offloadable to cold storage.

Core tenets:
- `subject_id` is stored only in `event_index`; `events` does not carry `subject_id` to avoid drift.
- `event_index` remains queryable even when old `events` partitions are dropped.
- Older payloads can be archived externally; `event_index` rows can be marked as cold.

Current state:
- Single `event_index` table with indexes on `(subject_id, partition_month)`, `(subject_id, ts)`, and `(event_id)`.
- `events` is time-partitioned monthly and can be dropped by partition for retention.

Potential evolution paths:
1. Time range partitions for `event_index` (keep old index partitions when dropping `events`).
2. Hash partitions for `event_index` by `subject_id` (64–256 shards), optionally with time subpartitioning.
3. Two-tier: keep recent `event_index` per-event rows; replace very old per-event rows with a `event_index_cold_manifest` holding per-subject-per-month chunk pointers to external storage (e.g., S3).

Cold tier metadata (additive columns on `event_index`):
- `storage_tier` CHECK in ('hot','cold') DEFAULT 'hot'
- `archived_at TIMESTAMPTZ`
- `storage_uri TEXT` or `storage_meta JSONB`

Operational guidelines:
- Cap ingest batch sizes; create only required partitions for present months.
- Schedule `REFRESH MATERIALIZED VIEW CONCURRENTLY` for routing/summary MVs.
- Align retention jobs: drop `events` partitions, mark `event_index` rows as cold (or migrate to manifests), and prune `ingest_spill` rows.
- Plan periodic `REINDEX CONCURRENTLY` and tuned autovacuum settings per partition if/when partitioning `event_index`.


