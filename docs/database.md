## Database Reference

### Overview
Normalized event storage with monthly partitioning and a canonical index for routing and constraints. Incremental statistics tables provide lightweight rollups for common analytics in development and dashboards.

### Core Tables
- `public.schemas(schema_id uuid primary key, name text, version int, body jsonb, status text, created_at timestamptz)`
- `public.producers(producer_id uuid primary key, name text unique, description text, created_at timestamptz, disabled_at timestamptz)`
- `public.subjects(subject_id uuid primary key, subject_key text unique, attrs jsonb, first_seen_at timestamptz, last_seen_at timestamptz)`
 - `public.subjects(subject_id uuid primary key, subject_key text unique, attrs jsonb, current_schema_id uuid null, first_seen_at timestamptz, last_seen_at timestamptz)`
- `public.producer_subjects(producer_id uuid, subject_id uuid, primary key(producer_id, subject_id))`
- `public.subject_schemas(subject_id uuid, schema_id uuid, primary key(subject_id, schema_id))`
- `public.tags(tag_id bigserial primary key, key citext, value citext, unique(key, value))`
- `public.event_index(event_id uuid primary key, ts timestamptz not null, subject_id uuid null, partition_month date generated always as (date_trunc('month', ts)::date) stored)`
- `public.events(event_id uuid, partition_month date, producer_id uuid, schema_id uuid, payload jsonb, received_at timestamptz default now(), primary key(event_id, partition_month)) partition by LIST(partition_month)`
- `public.event_tags(event_id uuid, partition_month date, tag_id bigint, primary key(event_id, partition_month, tag_id)) partition by LIST(partition_month)`
- `public.ingest_spill(spill_id bigserial primary key, event_id uuid, ts timestamptz, subject_id uuid, producer_id uuid, schema_id uuid, payload jsonb, tags jsonb, error text, received_at timestamptz)`

Indexes and constraints:
- BRIN on `event_index(ts)` and `(subject_id, partition_month)`
- Check constraints on `event_index.ts` to bound acceptable time window
- Foreign keys from `events`/`event_tags` to `event_index(event_id)`

### Partitioning
`events` and `event_tags` are list-partitioned by `partition_month` (date). Helper: `public.ensure_month_partitions(from_month date, months_ahead int)` creates missing child tables and local indexes for the requested months.

### Ingest Function
`public.ingest_events(_events jsonb) returns table(events_inserted bigint, tags_linked bigint)`
- Validates required fields and batch size, guards time window, rejects duplicate `event_id`.
- Ensures monthly partitions for months present in the batch.
- Inserts into `event_index` first, then into `events` and `event_tags` with `ON CONFLICT DO NOTHING`.
- Captures rows inserted in this call and updates incremental statistics:
  - `public.stats_event_month(partition_month, event_count)`
  - `public.stats_tag_month(tag_id, partition_month, event_count)`
- On failure during partitioning or insert, spills the entire batch to `public.ingest_spill` with error text and returns zeros.

Returned counts:
- `events_inserted`: number of `events` persisted in this call
- `tags_linked`: number of `event_tags` links persisted in this call

### Triggers
Prevent updates that would mutate identity properties:
- `trg_events_prevent_identity_change` on `public.events` via `public.prevent_events_identity_change()`
- `trg_event_index_prevent_identity_change` on `public.event_index` via `public.prevent_event_index_identity_change()`

### Materialized Views
- `public.subject_months_mv(subject_id, partition_month, event_count)`
- `public.tag_months_mv(tag_id, partition_month, event_count)`

These are built from base tables and indexed on their natural keys.

### Incremental Statistics
Tables updated by `ingest_events` using only rows inserted in the current call:
- `public.stats_event_month(partition_month primary key, event_count bigint)` totals by month
- `public.stats_tag_month(tag_id, partition_month, event_count, primary key(tag_id, partition_month))` tag totals by month

### Developer Views
Convenience, read-only views:
- `events_recent`: last 1,000 events with resolved names
- `events_with_tags_recent`: last 1,000 events with aggregated tags
- `partition_sizes`: size by child tables of `events` and `event_tags`
- `tag_popularity_month`: reads from `stats_tag_month` for last 6 months
- `event_volume_month`: reads from `stats_event_month` for last 12 months

### Storage and Compression
`public.events` TOAST compression prefers `lz4` when available, falling back to `pglz`.

### Permissions
Public DML is revoked on `events`, `event_tags`, `event_index`. Role `fdc-kernel` is granted `EXECUTE` on `public.ingest_events(jsonb)` if present.

### Subject helpers
- `public.set_current_subject_schema(subject_id, schema_id)` sets `subjects.current_schema_id` and appends to `subject_schemas` if missing.


