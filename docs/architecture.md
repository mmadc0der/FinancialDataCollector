## Architecture

### Components
- Kernel: core orchestrator. Responsibilities: module supervision, protocol server, routing to sinks, backpressure, config, telemetry.
- Collector Module: per-broker/exchange adapter. Encapsulates auth, API nuances, rate limits, reconnection, and maps remote payloads to normalized events.
- Sinks: pluggable outputs (initial: NDJSON file with rotation). Future: Redis Streams, SQLite/WAL, Parquet batcher.

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
- Transport: WebSocket. One connection per module instance. Bidirectional: module->kernel data; kernel->module control.
- Message envelope:
  - type: data|heartbeat|control|ack|error
  - version: semver of protocol
  - id: ULID of message
  - ts: nanoseconds epoch at sender
  - data: event or control payload

### Supervision
- Each module runs as a separate process. Kernel supervises via a module runner and health pings.
- Hot-reload: on config change or new binary/script, kernel restarts module with exponential backoff and jitter. Rolling apply: per module instance.
- Isolation: stdio and WS boundaries; kernel enforces rate limits and message size/time.

### Resilience/backpressure
- Kernel maintains bounded queues. When sinks are slow, kernel can drop non-critical events under configured policy (e.g., sample quotes) but never control/heartbeats.
- Per-connection flow control via credit-based acks (window size N). Module sends up to N unacked messages.

### Time/ordering
- Kernel annotates `ts_kernel` on ingest. Ordering is per connection. Cross-connection ordering is best-effort; sinks include connection id.

### Configuration
- `config/kernel.yaml`: global (ports, limits, sinks). `modules.d/*.yaml`: module definitions (command, args/env, credentials via env/secret files).

### Observability
- Structured logging (JSON). Metrics via Prometheus on localhost port. Health endpoints.

