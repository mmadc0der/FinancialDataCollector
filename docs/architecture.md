## Architecture

### Components
- Kernel: core orchestrator. Responsibilities: Redis ingest (consumer group), routing to Postgres (primary), filesystem spill only on Postgres connectivity loss (auto-replay/erase), backpressure, config, telemetry, and strict auth for producers/admins.
- Collector Module: external processes publish to Redis Streams; they are not supervised by the kernel.
- Sinks: Postgres (primary), spill files only on PG outages. Redis Streams is the ingress bus.

### Data model (normalized, type-agnostic events)
Core tables:
- `schemas(schema_id uuid, name, version, body jsonb)`
- `producers(producer_id uuid, name)`
- `subjects(subject_id uuid, subject_key, attrs jsonb)`
- `tags(tag_id bigserial, key citext, value citext)`
- See `docs/database.md` for the canonical schema. Core relations include `schemas`, `producers`, `subjects`, `tags`, `event_index`, partitioned `events`, and partitioned `event_tags`.

Notes:
- Event IDs are stored as UUID (uuidv7 recommended at the edge). No TEXT IDs.
- Payload is a single JSON object; if raw is in object storage, include its URI inside payload.
- Tags are normalized via `tags` and `event_tags`.

Incomplete (to be implemented):
- Producer registration and authentication by tokens, mapping to `producer_id` UUIDs at ingest. Temporary config-based IDs will be removed; do not rely on them.

### Protocol boundary
- Data-plane: Redis Streams. Modules XADD lean events into `events`. Kernel consumes via consumer group `kernel`.
- No envelopes. Fixed streams:
  - `fdc:register` → `fdc:register:resp`
  - `fdc:subject:register` → `fdc:subject:resp`
  - `fdc:token:exchange` → `fdc:token:resp`
- Registration binds or creates a `producer_id` and records as `pending`; token issuance happens only via token exchange.

### Supervision
- Not applicable. Modules are external and not managed by the kernel.

### Resilience/backpressure
- Redis Streams provides durable decoupling (at-least-once). Kernel acknowledges messages only after Postgres commit or successful spill write; DLQ on parse/validation errors.
- Kernel batches to Postgres with backoff; on Postgres connectivity failures only, spills to disk and replays when connectivity is restored. Bounded internal queues with drop policy for extreme pressure.

### Time/ordering
- Kernel annotates `ts_kernel` on ingest. Ordering is per connection. Cross-connection ordering is best-effort; sinks include connection id.

### Configuration
- `config/kernel.yaml`: server, postgres, redis, logging, auth settings.
  - Redis and Postgres are required; the kernel refuses to start without them.
  - Auth is mandatory: tokens are required on every event; registration and admin endpoints require OpenSSH certificates signed by configured CAs (`producer_ssh_ca`, `admin_ssh_ca`).

### Observability
- Structured logging (JSON). Metrics via Prometheus on `/metrics`. Health endpoints at `/healthz` and `/readyz`.
- Key metrics: `kernel_redis_read_total`, `kernel_redis_ack_total`, `kernel_redis_dlq_total`, `kernel_redis_batch_seconds`, `kernel_pg_batch_size`, `kernel_pg_batch_seconds`.
  - Auth: `kernel_auth_denied_total` increments on rejected unauthenticated messages.

