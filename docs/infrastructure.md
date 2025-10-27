## Infrastructure: Redis and Postgres

This guide describes creating service users and configuring the kernel to use Redis and Postgres.

### Postgres

Assumptions:
- Postgres 13+ is running locally or reachable.
- You have superuser access to run `psql`.

Create user, database, and grants:

```bash
psql -h 127.0.0.1 -U postgres -W <<'SQL'
CREATE ROLE data_kernel WITH LOGIN PASSWORD 'CHANGE_ME_STRONG';
CREATE DATABASE data_kernel_db OWNER data_kernel;
\c data_kernel_db
GRANT ALL PRIVILEGES ON DATABASE data_kernel_db TO data_kernel;
-- Future tables will grant automatically via default privileges:
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO data_kernel;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO data_kernel;
SQL
```

Apply migrations (idempotent; safe to re-run in order):

```bash
psql -h 127.0.0.1 -U data_kernel -d data_kernel_db -W -f migrations/0001_init.sql | cat
psql -h 127.0.0.1 -U data_kernel -d data_kernel_db -W -f migrations/0002_db_features.sql | cat
psql -h 127.0.0.1 -U data_kernel -d data_kernel_db -W -f migrations/0003_dev_views.sql | cat
```

See `docs/database.md` for the schema, ingest function, partitioning helper, stats tables, and dev views.

Start from `config/kernel.example.yaml`: copy it to `config/kernel.yaml` and update values.

Kernel configuration (example):

```yaml
postgres:
  enabled: true
  dsn: "postgres://data_kernel:CHANGE_ME_STRONG@127.0.0.1:5432/data_kernel_db?sslmode=disable"
  max_conns: 8
  conn_max_lifetime_ms: 600000
  apply_migrations: true
```

### Redis

Assumptions:
- Redis 6+ with ACLs enabled.

Create an ACL user with limited permissions for publishing to a stream:

```bash
redis-cli <<'REDIS'
ACL SETUSER data_kernel on >CHANGE_ME_STRONG ~fdc:* +xadd +ping +auth +client
SAVE
REDIS
```

Kernel configuration (example):

```yaml
redis:
  enabled: true
  addr: "127.0.0.1:6379"
  username: "data_kernel"
  password: "CHANGE_ME_STRONG"
  db: 0
  key_prefix: "fdc:"
  stream: "events"
  maxlen_approx: 1000000
```

### Security notes
- Store passwords as environment variables or secret files; avoid committing secrets.
- Prefer local loopback or VPN; add TLS in front of Redis/Postgres when exposed.
- SSH identities:
  - Kernel signing key: store under `ssh/kernel_sign` and reference via `auth.private_key_file`.
  - Producer CA: generate once and store under `modules.d/ssh/producer_ca` (private) and `producer_ca.pub` (public). Put the public key into `auth.producer_ssh_ca`.
  - Use `scripts/producer_ca.sh init-ca` to create the producer CA and `scripts/producer_ca.sh sign -k <producer>.pub -I <id> -n producer` to issue producer certs.

### Admin mTLS and detached signature (required)
- Generate an Admin X.509 CA and issue client certs for admins. Provide the Admin CA PEM as `server.tls.client_ca_file` and set `require_client_cert: true`.
- Configure server TLS cert/key via `server.tls.cert_file` and `server.tls.key_file`.
- Generate an OpenSSH Admin CA and issue SSH certificates for admin keys. Put the Admin SSH CA public key in `auth.admin_ssh_ca`.
- Set `auth.admin_principal` to the SSH certificate principal (e.g., `fdc-admin`). Optionally set `auth.admin_allowed_subjects` to allowed X.509 subjects.
- Each admin request must include:
  - `X-Admin-Cert`: OpenSSH user certificate (public), signed by Admin SSH CA
  - `X-Admin-Nonce`: random nonce (unique per request)
  - `X-Admin-Signature`: base64 Ed25519 signature over `canonicalJSON(body)+"\n"+METHOD+"\n"+PATH+"\n"+nonce`

### Observability
- Postgres: enable `log_min_duration_statement` for slow queries.
- Redis: monitor memory usage.
- Prometheus: scrape `/metrics` on the kernel (add job in Prometheus config).
- Grafana: import the dashboard JSON in `docs/grafana/kernel.json`.
- Security KPIs available:
  - `kernel_admin_mtls_denied_total`, `kernel_admin_signature_invalid_total`, `kernel_admin_replay_total`
  - `kernel_canonical_verify_fail_total`
  - `kernel_rate_limit_allow_total{op=...}`, `kernel_rate_limit_deny_total{op=...}`

### Authentication setup
- Generate Ed25519 keypair; encode keys as base64 (raw).
- Configure `auth` block in `config/kernel.yaml` with issuer/audience, `public_keys` map, and `admin_token`.
- Fixed streams:
  - `fdc:register` / `fdc:register:resp`
  - `fdc:subject:register` / `fdc:subject:resp`
  - `fdc:token:exchange` / `fdc:token:resp`
- Use `POST /auth/review` to approve/deny keys and bind producers; use `POST /auth/revoke` to revoke tokens. Tokens are issued via `fdc:token:exchange` only.

