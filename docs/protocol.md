## Kernel ↔ Module Protocol (lean v1)

### Transport
- Data-plane: Redis Streams. Modules publish to `events` with XADD. Fields:
  - `payload`: the event JSON (lean, heavy payload should be exported to S3 and linked in payload)
  - `token`: producer auth token (always required)
  The kernel consumes with XREADGROUP and acknowledges after durable write.

### Event JSON (payload)
```json
{
  "event_id": "uuidv7",
  "ts": "RFC3339Nano",
  "subject_id": "<uuid>",
  "payload": { /* producer-defined contents */ },
  "tags": [{"key":"core.symbol","value":"AAPL"}]
}
```
- The kernel derives `producer_id` from the token and resolves `schema_id` for the `subject_id` via Redis cache → DB.
- It enforces `producer_subjects(producer_id, subject_id)` and that the subject has a current schema.

### Subject registration
- Stream: `fdc:subject:register` (fixed). Fields:
  - `token`: producer token
  - `payload`: `{ "subject_key": "...", "schema_id": "...", "attrs"?: {...} }`
- Behavior: ensure subject by key, set `current_schema_id` and append to history, bind producer↔subject.
- Response: `fdc:subject:resp:<producer_id>` with `{ subject_id }`.

### Authentication
- Tokens are EdDSA-signed and include `iss`, `aud`, `exp`, `nbf`, `jti`, `sub` (producer_id), and optional `sid` (subject_id). Kernel validates signature and JTI allowlist/blacklist; Redis cache accelerates checks.
- If `sid` present, it must match the event’s `subject_id`.

### Producer registration
- Stream: `fdc:register` (fixed) with fields `{ pubkey, payload, nonce, sig }`.
- **New Registration Flow (v2)**:
  - **Case 1 (New Producer)**: Unknown fingerprint, no `producer_id` in payload → creates new producer, key status=`pending`
  - **Case 2 (Key Rotation)**: Unknown fingerprint, WITH `producer_id` in payload → validates existing producer, key status=`pending`
  - **Case 3 (Known Approved)**: Known fingerprint, status=`approved` → returns existing `producer_id`
  - **Case 4 (Known Pending)**: Known fingerprint, status=`pending` → silent (no response)
  - **Case 5 (Known Denied)**: Known fingerprint, status=`revoked`/`superseded` → returns denial
- Response: `fdc:register:resp:<nonce>` with `{ fingerprint, producer_id, status, reason? }` (per-request ephemeral).
- **Rate Limiting**: Kernel-side enforcement (default 10 RPM), silent drop on limit exceeded.
- **Anti-replay**: nonces cached with TTL; duplicate nonces rejected; DB uniqueness enforced.
- **Admin Review**: Keys require manual approval via `POST /auth/review` before becoming `approved`.

### Token exchange
- Stream: `fdc:token:exchange` (fixed) with fields `{ pubkey?, token?, payload, nonce, sig? }`.
- If using `pubkey`: the signature must be made with an OpenSSH certificate signed by `producer_ssh_ca`, and the key must be **approved** and bound to `producer_id`.
- If using `token`: verify claims and allow short-lived renewal.
- **Key Status Validation**: Only keys with status=`approved` can exchange for tokens.
- Response: `fdc:token:resp:<producer_id>` with `{ fingerprint, producer_id, token, exp }`.

### Auth Endpoints
- `GET /auth`: view pending registrations
- `POST /auth/review`: approve/deny producer registrations
- `POST /auth/revoke`: revoke issued tokens
All admin requests must include `X-SSH-Cert` carrying an OpenSSH certificate signed by `admin_ssh_ca` and `X-SSH-Principal`.

### Deregistration
- Stream: `fdc:register` with `{ action: "deregister", pubkey, payload, nonce, sig }`.
- On valid signature and known binding, kernel sets `producers.disabled_at` and responds on `fdc:register:resp:<nonce>` with `{ status: "deregistered" }`.
- Disabled producers' events are rejected (`producer_disabled`) until re-registration.

### Limits and DLQ
- Max message size: configurable.
- DLQ reasons include: `unauthenticated`, `bad_event_json`, `subject_mismatch_token`, `producer_subject_forbidden`, `missing_subject_schema`.

