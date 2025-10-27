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
- Registration, subject ops, and token exchange signatures must use an OpenSSH certificate signed by `producer_ssh_ca`, and must sign canonical JSON: `canonical(payload)+"."+nonce`.
- Admin endpoints require mTLS (client cert signed by Admin X.509 CA) and a detached Ed25519 signature with an OpenSSH certificate signed by `admin_ssh_ca`. Each admin request must include headers:
  - `X-Admin-Cert`: OpenSSH user certificate (public)
  - `X-Admin-Nonce`: unique nonce (replay-protected)
  - `X-Admin-Signature`: base64 signature over `canonicalJSON(body)+"\n"+METHOD+"\n"+PATH+"\n"+nonce`
- Streams (fixed):
  - Producer registration: publish to `fdc:register`; responses on `fdc:register:resp:<nonce>`.
  - Subject registration: publish to `fdc:subject:register`; responses on `fdc:subject:resp:<producer_id>`.
  - Token exchange: publish to `fdc:token:exchange`; responses on `fdc:token:resp:<producer_id>`.
- Auth endpoints:
  - `GET /auth` — view pending registrations
  - `POST /auth/review` — approve/deny producer registrations
  - `POST /auth/revoke` — revoke issued tokens (`{ "jti": "<token_id>", "reason": "..." }`)

### Security model and assumptions
- Integrity and producer authority are primary objectives; confidentiality of event payloads is out of scope.
- Trust boundaries: producers ↔ Redis streams; kernel ↔ Postgres/Redis; admin HTTP.
- Producer authority:
  - OpenSSH certificates signed by `producer_ssh_ca`; key status in DB must be `approved`.
  - Signatures over canonical JSON eliminate ambiguity across clients.
  - Replay defenses: Redis `SETNX` nonces (per flow) and DB uniqueness (e.g., `(fingerprint, nonce)` for registrations).
  - Event integrity: `event_index(event_id)` canonical gate; duplicate IDs rejected.
- Admin authority:
  - mTLS is mandatory (Admin X.509 CA). No proxy header fallbacks.
  - Detached signature required with OpenSSH admin certificate; principal must match `auth.admin_principal`.
  - Nonce replay protection for admin requests.
- Availability and abuse controls:
  - Distributed rate limiting via Redis Lua token bucket per operation and identity (`op:id`).
  - Control-plane ops fail closed on Redis unavailability; data-plane uses DLQ on auth failures.
- Observability:
  - Security KPIs exported: admin mTLS denials, admin signature invalid, admin replays, canonical verify failures, rate limit allow/deny per op.

### Deployment hardening checklist
- Configure `server.tls.cert_file`, `server.tls.key_file`, and `server.tls.client_ca_file`; set `server.tls.require_client_cert: true`.
- Set `auth.admin_ssh_ca`, `auth.admin_principal`, and optionally `auth.admin_allowed_subjects`.
- Set `auth.producer_ssh_ca`; ensure producers use SSH certificates.
- Restrict kernel listen address to a management network.
- Provision Redis with ACLs; scope keys under a unique `key_prefix`.
- Monitor: Prometheus scrape `/metrics`; import Grafana dashboard in `docs/grafana/kernel.json`.

### Infrastructure setup
- See `docs/infrastructure.md` for Redis and Postgres setup and configuration. Both are required.
- Initial Postgres migration: `migrations/0001_init.sql`.

