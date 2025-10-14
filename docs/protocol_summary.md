## Producer ↔ Kernel Protocol (v0.1.0)

- **Transport**: Redis Streams. Modules XADD to `fdc:events` (configurable). Fields:
  - `id`: producer message id (ULID recommended)
  - `payload`: JSON envelope bytes (see Envelope)
  - `token` (optional/required by config): producer auth token
- **Acking**: Kernel ACKs after durable persistence (Postgres commit) or successful spill write.
- **DLQ**: Invalid/unauthed payloads go to `fdc:events:dlq` with `error` field.

### Envelope
```json
{
  "version": "0.1.0",
  "type": "data|heartbeat|control|ack|error",
  "id": "ULID",
  "ts": 1730000000000000000,
  "data": { /* kind-specific */ }
}
```
- Kernel validates shape via `internal/protocol.ValidateEnvelope`.

### Registration & Refresh
- Stream: `fdc:register` (configurable). Fields:
  - `pubkey`: OpenSSH public key (text). If `producer_cert_required`, must be an SSH cert signed by configured CA.
  - `payload`: canonical JSON (stable key order)
  - `nonce`: random string
  - `sig`: base64 signature over `payload + "." + nonce` using Ed25519 private key corresponding to `pubkey`
- Kernel steps: fingerprint pubkey (SHA256, base64), verify signature, upsert key, record registration, auto-issue token if key approved and bound.
- Response (optional): on auto-issue, kernel publishes `{fingerprint, token, producer_id}` to `register_resp_stream`.

### Authentication
- Tokens: EdDSA over header+claims, with `iss`, `aud`, `sub` (producer_id), `jti`, `exp`, `nbf`, optional `fp` (fingerprint).
- Kernel verifies signature and that JTI exists and is not revoked (Redis cache + Postgres).
- Include token as XADD `token` field.

### Limits & Flow Control
- Max message size: `server.max_message_bytes`.
- Kernel reads in batches and acks after persistence; publishers should trim streams (`MAXLEN ~`).
- Backpressure: kernel drops enqueue when internal queues are full (message goes pending until retry or DLQ on parse/auth fail).
