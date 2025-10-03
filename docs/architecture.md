## Architecture

### Components
- Kernel: core orchestrator. Responsibilities: Redis ingest (consumer group), routing to Postgres (primary), spill-to-disk fallback, optional Redis re-publish, backpressure, config, telemetry.
- Collector Module: external processes publish to Redis Streams; they are not supervised by the kernel.
- Sinks: Postgres (primary), spill files only on PG outages. Redis Streams is the ingress bus.

### Data model (normalized event)
Minimal schema to unify spot/derivatives:
- event_type: quote|trade|orderbook|ohlc|heartbeat|status
- source: broker/exchange identifier
- symbol: instrument identifier (e.g., BTC-USD)
- ts_event: nanosecond epoch of exchange event
- ts_collector: nanosecond epoch at module
- ts_kernel: nanosecond epoch at kernel ingest
- payload: object (type-specific fields). Include sequence numbers when available.
- meta: object (module version, region, connection id)

### Protocol boundary
- Data-plane: Redis Streams. Modules XADD into `events` (or per-module streams). Kernel consumes via consumer group `kernel`.
- Message envelope:
  - type: data|heartbeat|control|ack|error
  - version: semver of protocol
  - id: ULID of message
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
- `config/kernel.yaml`: global (ports, limits, sinks). `modules.d/*.yaml`: module definitions (command, args/env, credentials via env/secret files).

### Observability
- Structured logging (JSON). Metrics via Prometheus on localhost port. Health endpoints.
- Key metrics: `kernel_redis_read_total`, `kernel_redis_ack_total`, `kernel_redis_dlq_total`, `kernel_redis_batch_seconds`, `kernel_pg_batch_size`, `kernel_pg_batch_seconds`.

