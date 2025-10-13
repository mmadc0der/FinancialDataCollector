## Data Kernel (Redis ingest, Postgres-first)

This project provides a resilient, configurable kernel for ingesting high-frequency financial market data from Redis Streams and persisting normalized timeseries events into Postgres, with spill-to-disk fallback and optional Redis re-publish.

### High-level goals
- Per-second (or higher) updates with rich event payloads
- Strict `collector-module` ↔ `kernel` boundary via Redis Streams
- Fault-tolerant kernel with backpressure, batching, and DLQ
- Vendor-neutral, no enterprise licenses, single-node friendly

### Tech stack
- Kernel: Go 1.23+
- Modules: external producers (any language) publishing to Redis Streams
- Transport: Redis Streams (JSON envelopes)
- Storage: Postgres (primary), spill-to-disk as fallback; optional Redis re-publish
- Config: YAML
- CI: GitHub Actions

See `docs/architecture.md`, `docs/protocol.md`, and `docs/verification.md`.

### Quick start
- Build: `make build` or `go build -o bin/kernel ./cmd/kernel`
- Copy config: `cp config/kernel.example.yaml config/kernel.yaml` and edit values
- Run: `./bin/kernel --config ./config/kernel.yaml`

### Authentication (optional)
- Configure `auth` in `config/kernel.yaml` (issuer, audience, Ed25519 keys). When enabled, producers must include a `token` field on XADD.
 - Admin endpoints:
   - List pending registrations: `GET /admin/pending`
   - Approve fingerprint and issue token: `POST /admin/approve` with body `{"fingerprint":"...","name":"...","schema_id":"...","ttl_seconds":86400}`
   - Revoke token: `POST /admin/revoke` with body `{"jti":"<token_id>","reason":"..."}`
  - Production hardening: send OpenSSH cert in `X-SSH-Cert` with principal in `X-SSH-Principal` signed by configured CA.

### Infrastructure setup
- See `docs/infrastructure.md` for Redis and Postgres setup and configuration.
- Initial Postgres migration: `migrations/0001_init.sql`.

