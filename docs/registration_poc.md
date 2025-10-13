## Producer Registration & Token Refresh - PoC and Security Audit

### Goals
- Automate producer onboarding and token refresh while enforcing strict authentication.
- Avoid broad login capability; rely on signed requests and admin approval.
- Keep data-plane unencrypted but ensure only authenticated producers can write events.

### Design Overview
- Redis registration stream (`fdc:register`, configurable): producers submit signed requests.
- OpenSSH-style public keys for producers are used to verify signatures and derive fingerprints.
- Postgres keeps:
  - `producer_keys(fingerprint, pubkey, status[pending|approved|revoked], producer_id)`
  - `producer_registrations(reg_id, fingerprint, payload, sig, nonce, ts, status, reviewer, reason)`
  - `producer_tokens` and `revoked_tokens` (from previous migration) remain authoritative for issuance/blacklist.
- Auto-issue policy: if fingerprint is approved and bound to a `producer_id`, issue a short-lived token without admin approval.
- Unknown/first-time fingerprints are recorded as `pending` for admin approval.
- Admin API is protected by an OpenSSH CA public key (for production hardening; PoC keeps shared admin token fallback).

### Message Format (registration stream)
- XADD fields:
  - `pubkey`: OpenSSH public key (text)
  - `payload`: JSON string, e.g. `{ "producer_hint": "binance", "contact": "ops@example.com", "meta": {"region":"eu"} }`
  - `nonce`: random string (>=16 bytes)
  - `sig`: base64 signature over `SHA256(payload||"."||nonce)` using the corresponding `pubkey`'s private key

### Verification Steps
1. Parse and canonicalize `payload` (raw string ok); concatenate `payload + "." + nonce`.
2. Compute SHA256 digest; verify signature with the provided `pubkey`.
3. Derive fingerprint (SHA256 over public key bytes, base64) and upsert into `producer_keys` if new (pending).
4. Create `producer_registrations` row with status `pending`.
5. If `producer_keys.status=approved` and `producer_id` set, auto-issue a token (short TTL) and mark registration `auto_issued`.
6. Ack after durable writes.

### Admin Workflow
- Admin reviews pending registrations, approves key and assigns/binds `producer_id`.
- Admin can issue long-lived tokens via `/admin/issue` and revoke via `/admin/revoke`.
- Admin requests must be authenticated with OpenSSH certificates signed by a configured CA (PoC: stubbed; fallback header `X-Admin-Token`).

### Security Audit & Risks
- Replay of registration messages: mitigated by nonce and storing recent nonces per fingerprint (future improvement: add `producer_registrations(nonce UNIQUE)` or TTL cache). PoC leaves as follow-up.
- Key substitution: signature verifies against provided `pubkey`, but binding is explicit and requires admin approval; auto-issue only when key is already approved and bound.
- Token refresh abuse: rate-limit auto-issue per fingerprint (PoC: not yet enforced; add Redis key with TTL to limit refresh cadence).
- DLQ exposure: registration stream should be separate from data stream; registration payloads should not contain secrets. Sig relies on SSH key; no secrets in Redis.
- Admin CA verification: in PoC we retain shared token; production should validate `ssh-cert` headers with CA and principals.
- Database availability: auth/token gating requires Postgres reachability; spill-only mode should keep rejecting unauthenticated events.

### Future Hardening
- Enforce unique `nonce` per fingerprint for a time window (DB unique constraint or Redis set with TTL).
- Implement auto-issue rate limits per fingerprint and global caps.
- Add a response channel for registration outcomes (e.g., `fdc:register:resp:<fingerprint>` or per-producer queue).
- Replace shared admin token with mandatory OpenSSH certificate verification middleware.

### PoC Implementation Status
- DB migrations added (`0005_registration.sql`).
- Config extended for `redis.register_stream` and `auth.admin_ssh_ca`.
- Kernel spawns register consumer stub; logs init.
- Admin endpoints exist; verification via CA not yet implemented (stubbed).
- Protocol and architecture docs updated to reflect flows.
