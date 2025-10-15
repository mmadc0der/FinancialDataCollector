## Kernel ↔ Module Protocol (lean v1)

### Transport
- Data-plane: Redis Streams. Modules publish to `events` with XADD. Fields:
  - `payload`: the event JSON (lean)
  - `token`: producer auth token (required when auth is enabled)
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
- Unknown fingerprints: recorded as `pending` and bound to a newly created or existing `producer_id`.
- Response: `fdc:register:resp:<nonce>` with `{ fingerprint, producer_id, status }` (per-request ephemeral).
- Anti-replay: nonces cached with TTL; duplicate nonces rejected; DB uniqueness enforced.

### Token exchange
- Stream: `fdc:token:exchange` (fixed) with fields `{ pubkey?, token?, payload, nonce, sig? }`.
- If using `pubkey`: verify signature and require approved binding to `producer_id`.
- If using `token`: verify claims and allow short-lived renewal.
- Response: `fdc:token:resp:<producer_id>` with `{ fingerprint, producer_id, token, exp }`.

### Deregistration
- Stream: `fdc:register` with `{ action: "deregister", pubkey, payload, nonce, sig }`.
- On valid signature and known binding, kernel sets `producers.disabled_at` and responds on `fdc:register:resp:<nonce>` with `{ status: "deregistered" }`.
- Disabled producers’ events are rejected (`producer_disabled`) until re-registration.

### Limits and DLQ
- Max message size: configurable.
- DLQ reasons include: `unauthenticated`, `bad_event_json`, `subject_mismatch_token`, `producer_subject_forbidden`, `missing_subject_schema`.

