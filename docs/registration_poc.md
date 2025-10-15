## Producer Registration & Token Exchange - PoC and Security Audit

### Goals
- Automate producer onboarding while enforcing strict authentication.
- Remove producer-side optionality; use fixed Redis streams for requests and responses.
- Keep data-plane unencrypted but ensure only authenticated producers can write events.

### Design Overview
- Redis registration stream `fdc:register` (fixed): producers submit signed requests.
- Responses are published to `fdc:register:resp:<nonce>` (per-request, ephemeral with TTL).
- OpenSSH-style public keys for producers are used to verify signatures and derive fingerprints.
- Postgres keeps:
  - `producer_keys(fingerprint, pubkey, status[pending|approved|revoked], producer_id)`
  - `producer_registrations(reg_id, fingerprint, payload, sig, nonce, ts, status, reviewer, reason)`
  - `producer_tokens` and `revoked_tokens` (from previous migration) remain authoritative for issuance/blacklist.
- Unknown/first-time fingerprints are recorded as `pending` for admin approval.
- Admin API is protected by an OpenSSH CA public key (PoC may keep a fallback shared admin token).

### Message Format (registration stream)
- XADD fields:
  - `pubkey`: OpenSSH public key (text)
  - `payload`: JSON string, e.g. `{ "producer_hint": "binance", "contact": "ops@example.com", "meta": {"region":"eu"} }`
  - `nonce`: random string (>=16 bytes)
  - `sig`: base64 signature over `SHA3-512(payload||"."||nonce)` using the corresponding `pubkey`'s private key

### Verification Steps
1. Canonicalize `payload` JSON to a deterministic string; concatenate `payload + "." + nonce`.
2. Verify signature with the provided `pubkey` over that exact byte sequence.
3. Derive fingerprint (SHA3-512 over public key bytes, base64).
4. Ensure producer existence: if the fingerprint is not bound to a `producer_id`, create a new `producers` row and bind the key to that `producer_id` (status `pending`).
5. Create `producer_registrations` row with status `pending` and include the resolved `producer_id`.
6. Acknowledge after durable writes and publish a response to `fdc:register:resp:<nonce>` with `{ fingerprint, producer_id, status }` and set a short TTL on the stream.

### Admin Workflow
- Admin reviews pending registrations, approves key (binding to the existing `producer_id`).
- Admin can revoke tokens via `/admin/revoke`.
- Admin requests must be authenticated with OpenSSH certificates signed by a configured CA.

### Security Audit & Risks
- Replay of registration messages: mitigated by nonce and storing recent nonces per fingerprint (future improvement: add `producer_registrations(nonce UNIQUE)` or TTL cache). Implemented best-effort Redis `SETNX reg:nonce:<fp>:<nonce>` with 1h TTL.
- Key substitution: signature verifies against provided `pubkey`, but binding is explicit and requires admin approval; auto-issue only when key is already approved and bound.
- Token exchange abuse: rate-limit token exchange per fingerprint.
- DLQ exposure: registration stream should be separate from data stream; registration payloads should not contain secrets. Sig relies on SSH key; no secrets in Redis.
- Admin CA verification: in PoC we retain shared token; production should validate `ssh-cert` headers with CA and principals.
- Database availability: auth/token gating requires Postgres reachability; spill-only mode should keep rejecting unauthenticated events.

### Future Hardening
- Enforce unique `nonce` per fingerprint for a time window (DB unique constraint or Redis set with TTL).
- Implement token-exchange rate limits per fingerprint and global caps.
- Enforce short TTL and auto-cleanup for `fdc:register:resp:<nonce>`.
- Replace shared admin token with mandatory OpenSSH certificate verification middleware.

### PoC Implementation Status
- DB migrations added (`0005_registration.sql`). `pgcrypto` is now created in `0001_init.sql`.
- Fixed request streams in use: `fdc:register`, `fdc:token:exchange`, `fdc:subject:register`.
- Response streams: `fdc:register:resp:<nonce>` (ephemeral), `fdc:token:resp:<producer_id>`, `fdc:subject:resp:<producer_id>`.
- Kernel register consumer implemented with nonce anti-replay and Ed25519 signature verification (via OpenSSH pubkey parse), records pending, and responds per-nonce with TTL.
- Admin approvals and revocations available; SSH CA verification implemented (with fallback header) via `X-SSH-Cert` and `X-SSH-Principal` against configured CA.
- Protocol and architecture docs updated to reflect flows.

### Token Exchange (separate stream)
- Stream: `fdc:token:exchange` (fixed); responses on `fdc:token:resp:<producer_id>`.
- Request may be authenticated by either:
  - a valid approved `pubkey` and signature over `payload + "." + nonce`, or
  - a still-valid short-lived token for renewal.
- Kernel issues a short-lived token when the fingerprint is approved and bound to the `producer_id` and returns `{ fingerprint, producer_id, token, exp }`.

### Deregistration
- Producers may send `{ action: "deregister", pubkey, payload, nonce, sig }` to `fdc:register`.
- On valid signature and known binding, the kernel sets `producers.disabled_at = now()` and responds on `fdc:register:resp:<nonce>` with `{ status: "deregistered" }`.
- While disabled, events from that `producer_id` are rejected (DLQ reason `producer_disabled`) until the next successful registration.

