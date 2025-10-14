## Producer ↔ Kernel Protocol (v0.1.0)

- **Scope for modules**: Producers do NOT send data-plane envelopes. They only publish control-plane requests to registration-related streams.

### Registration/Control Streams
- `fdc:register` (configurable): request producer registration or token refresh
  - `pubkey`: OpenSSH public key (text). If `producer_cert_required`, must be an SSH cert signed by configured CA.
  - `payload`: canonical JSON (stable key order)
  - `nonce`: random string
  - `sig`: base64 signature over `payload + "." + nonce` using Ed25519 private key corresponding to `pubkey`
- `fdc:subject:register` (optional, configurable): request subject registration/binding if enabled by kernel/admin policy

Kernel behavior:
- Fingerprint pubkey (SHA3-512, base64), verify signature over `SHA3-512(payload+"."+nonce)`.
- Upsert key and record registration as `pending`.
- If key is `approved` and bound to a `producer_id`, auto-issue a short-lived token and publish to `register_resp_stream`:
  - `{ fingerprint, token, producer_id }`

### IDs
- When kernel emits control envelopes (ack/error), it uses UUIDv7 for `id`.

### Authentication Tokens
- EdDSA tokens with claims: `iss`, `aud`, `sub` (producer_id), `jti`, `exp`, `nbf`, optional `fp` (fingerprint).
- Verified against configured public keys; JTI allowlist backed by Postgres with Redis cache.

### Limits
- Max registration message size: `server.max_message_bytes`.
- Nonce replay is prevented via Redis `SETNX` and DB unique `(fingerprint, nonce)`.
