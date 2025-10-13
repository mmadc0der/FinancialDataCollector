## Architecture

### Components
- Kernel: core orchestrator. Responsibilities: Redis ingest (consumer group), routing to Postgres (primary), spill-to-disk fallback, optional Redis re-publish, backpressure, config, telemetry, optional auth for producers.
- Collector Module: external processes publish to Redis Streams; they are not supervised by the kernel.
- Sinks: Postgres (primary), spill files only on PG outages. Redis Streams is the ingress bus.

### Data model (normalized, type-agnostic events)
Core tables:
- `schemas(schema_id uuid, name, version, body jsonb)`
- `producers(producer_id uuid, name, schema_id)`
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
- Data-plane: Redis Streams. Modules XADD into `events` (or per-module streams). Kernel consumes via consumer group `kernel`.
- Message envelope:
### Registration flow (optional)
- Stream: `fdc:register` (configurable). Kernel verifies producer signatures over registration payloads.
- Known, approved keys: auto-issue tokens (rate-limited) and respond out-of-band (admin reviews available in DB).
- Unknown keys: create `producer_keys` row in `pending` and `producer_registrations` pending record; admin approval binds fingerprint to `producer_id` and allows issuing.

  - type: data|heartbeat|control|ack|error
  - version: semver of protocol
  - id: UUIDv7 of message
  - ts: nanoseconds epoch at sender
  - data: event or control payload

### Supervision
- Not applicable. Modules are external and not managed by the kernel.

### Resilience/backpressure
- Redis Streams provides durable decoupling (at-least-once). Kernel acknowledges messages only after Postgres commit or successful spill write; DLQ on parse/validation errors.
- Kernel batches to Postgres with backoff; on failures, spills to disk and later replays. Bounded internal queues with drop policy for extreme pressure.

### Time/ordering
- Kernel annotates `ts_kernel` on ingest. Ordering is per connection. Cross-connection ordering is best-effort; sinks include connection id.

### Configuration
- `config/kernel.yaml`: server, postgres, redis, logging, spill settings.
  - `auth`: optional auth configuration (issuer, audience, Ed25519 keys, admin token, cache TTL).

### Observability
- Structured logging (JSON). Metrics via Prometheus on `/metrics`. Health endpoints at `/healthz` and `/readyz`.
- Key metrics: `kernel_redis_read_total`, `kernel_redis_ack_total`, `kernel_redis_dlq_total`, `kernel_redis_batch_seconds`, `kernel_pg_batch_size`, `kernel_pg_batch_seconds`.
  - Auth: `kernel_auth_denied_total` increments on rejected unauthenticated messages.

