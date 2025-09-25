## Data Distributor Kernel and Pluggable Collector Modules

This project provides a resilient, configurable kernel for ingesting high-frequency financial market data from pluggable, hot-reloadable collector modules, and distributing normalized timeseries events for downstream training and storage.

### High-level goals
- Per-second (or higher) updates with rich event payloads
- Strict `collector-module` ↔ `kernel` protocol boundary with encapsulated broker logic
- Hot-reload-like module lifecycle management with isolation and backoff
- Fault-tolerant kernel resistant to arbitrary module behavior
- Vendor-neutral, no enterprise licenses, single-node friendly

### Tech stack
- Kernel: Go 1.22+
- Collector modules: Polyglot (example: Python 3.10+)
- Transport: WebSocket (secure optional), JSON/NDJSON wire format
- Storage/Sinks: File NDJSON (rotated), optional Redis Stream/SQLite for demos
- Config: YAML/TOML
- CI: GitHub Actions

See `docs/architecture.md`, `docs/protocol.md`, and `docs/verification.md`.

# FinancialDataCollector