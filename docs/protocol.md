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
- Stream: `subject:register` (configurable). Fields:
  - `token`: producer token
  - `payload`: `{ "subject_key": "...", "schema_id"?: "...", "attrs"?: {...} }`
- Behavior: ensure subject by key, optionally set `current_schema_id` and append to history, bind producer↔subject. If `subject_resp_stream` is configured, kernel publishes `{subject_id}`.

### Authentication
- Tokens are EdDSA-signed and include `iss`, `aud`, `exp`, `nbf`, `jti`, `sub` (producer_id), and optional `sid` (subject_id). Kernel validates signature and JTI allowlist/blacklist; Redis cache accelerates checks.
- If `sid` present, it must match the event’s `subject_id`.

### Registration and refresh
- Stream: `register` with fields `{ pubkey, payload, nonce, sig }`.
- Unknown fingerprints: recorded as `pending` for admin approval.
- Known, approved fingerprints: kernel may auto-issue short-lived tokens and publish `{fingerprint, token, producer_id}` to `register_resp_stream` if configured.
- Anti-replay: nonces cached with TTL; duplicate nonces rejected; DB uniqueness enforced.

### Limits and DLQ
- Max message size: configurable.
- DLQ reasons include: `unauthenticated`, `bad_event_json`, `subject_mismatch_token`, `producer_subject_forbidden`, `missing_subject_schema`.

