## Producer ↔ Kernel Protocol (v0.1.0)

- No envelopes. Producers publish to fixed Redis Streams for registration, subjects, and token exchange.

### Streams (fixed)
- `fdc:register`: request producer registration
  - `pubkey`: OpenSSH public key (text). If `producer_cert_required`, must be an SSH cert signed by configured CA.
  - `payload`: canonical JSON (stable key order)
  - `nonce`: random string
  - `sig`: base64 signature over `payload + "." + nonce` using Ed25519 private key corresponding to `pubkey`
- `fdc:register:resp:<nonce>`: per-request registration results `{ fingerprint, producer_id, status }` (ephemeral)
- `fdc:subject:register`: request subject registration/binding
- `fdc:subject:resp:<producer_id>`: subject results `{ subject_id }`
- `fdc:token:exchange`: request a short-lived token (with approved pubkey or renewing a valid token)
- `fdc:token:resp:<producer_id>`: token results `{ fingerprint, producer_id, token, exp }`

Kernel behavior:
- Fingerprint pubkey (SHA3-512, base64), verify signature over `SHA3-512(payload+"."+nonce)`.
- Ensure/create `producer_id` and record registration as `pending` bound to that `producer_id`.
- Tokens are not issued during registration; use `fdc:token:exchange`.

### IDs
- When kernel emits responses (ack/error), it uses UUIDv7 for `id`.

### Authentication Tokens
- EdDSA tokens with claims: `iss`, `aud`, `sub` (producer_id), `jti`, `exp`, `nbf`, optional `fp` (fingerprint).
- Verified against configured public keys; JTI allowlist backed by Postgres with Redis cache.

### Limits
- Max registration message size: `server.max_message_bytes`.
- Nonce replay is prevented via Redis `SETNX` and DB unique `(fingerprint, nonce)`.
