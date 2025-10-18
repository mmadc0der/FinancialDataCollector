## Data Kernel (Redis ingest, Postgres-first)

This project provides a resilient kernel for ingesting high-frequency financial market data from Redis Streams and persisting normalized timeseries events into Postgres. The kernel always uses Redis and Postgres. Filesystem spill is used only during Postgres connectivity loss and is automatically replayed to Postgres and erased on success.

### High-level goals
- Per-second (or higher) updates with rich event payloads
- Strict `collector-module` ↔ `kernel` boundary via Redis Streams
- Fault-tolerant kernel with backpressure, batching, and DLQ
- Vendor-neutral, no enterprise licenses, single-node friendly

### Tech stack
- Kernel: Go 1.23+
- Modules: external producers (any language) publishing to Redis Streams
- Transport: Redis Streams (lean JSON events)
- Storage: Postgres (primary). Filesystem spill is used only during Postgres outages and is auto-replayed/erased on success.
- Config: YAML
- CI: GitHub Actions

See `docs/architecture.md`, `docs/protocol.md`, and `docs/verification.md`.

### Quick start
- Build: `make build` or `go build -o bin/kernel ./cmd/kernel`
- Copy config: `cp config/kernel.example.yaml config/kernel.yaml` and edit values
- Ensure Redis and Postgres are provisioned and reachable; the kernel requires both services.
- Run: `./bin/kernel --config ./config/kernel.yaml`
- Example producer: see `modules.d/producer-example/` (uses `fdc:subject:register` and lean events)

### Authentication
- Producers must include `token` on every event XADD.
- Registration and token exchange signatures must use an OpenSSH certificate signed by `producer_ssh_ca`; plain public keys are not accepted.
- Admin requests must include an OpenSSH certificate signed by `admin_ssh_ca` via `X-SSH-Cert` and principal in `X-SSH-Principal`.
- Streams (fixed):
  - Producer registration: publish to `fdc:register`; responses on `fdc:register:resp`.
  - Subject registration: publish to `fdc:subject:register`; responses on `fdc:subject:resp`.
  - Token exchange: publish to `fdc:token:exchange`; responses on `fdc:token:resp`.
- Auth endpoints:
  - `GET /auth` — view pending registrations
  - `POST /auth/review` — approve/deny producer registrations
  - `POST /auth/revoke` — revoke issued tokens (`{ "jti": "<token_id>", "reason": "..." }`)

### Infrastructure setup
- See `docs/infrastructure.md` for Redis and Postgres setup and configuration. Both are required.
- Initial Postgres migration: `migrations/0001_init.sql`.

