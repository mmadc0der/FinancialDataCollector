## Producer Registration & Token Exchange - PoC and Security Audit

### Goals
- Automate producer onboarding while enforcing strict authentication.
- Remove producer-side optionality; use fixed Redis streams for requests and responses.
- Keep data-plane unencrypted but ensure only authenticated producers can write events.

### Design Overview (v2 - Enhanced Security)
- Redis registration stream `fdc:register` (fixed): producers submit signed requests.
- Responses are published to `fdc:register:resp:<nonce>` (per-request, ephemeral with TTL).
- OpenSSH-style public keys for producers are used to verify signatures and derive fingerprints.
- Postgres keeps:
  - `producer_keys(fingerprint, pubkey, status[pending|approved|revoked|superseded], producer_id NOT NULL, superseded_at)`
  - `producer_registrations(reg_id, fingerprint, payload, sig, nonce, ts, status[pending|approved|rejected], reviewer, reason)`
  - `producer_tokens` and `revoked_tokens` (from previous migration) remain authoritative for issuance/blacklist.
- **Enhanced Registration Flow**:
  - **New Producer**: Unknown fingerprint, no `producer_id` → creates producer, key status=`pending`
  - **Key Rotation**: Unknown fingerprint, WITH `producer_id` → validates existing producer, key status=`pending`
  - **Known Keys**: Returns existing status (approved/pending/denied)
- **Rate Limiting**: Kernel-side enforcement (default 10 RPM), silent drop on limit exceeded.
- Admin API is protected by an OpenSSH CA public key with `/admin/review` endpoint for approve/deny actions.

### Message Format (registration stream)
- XADD fields:
  - `pubkey`: OpenSSH public key (text)
  - `payload`: JSON string, e.g. `{ "producer_hint": "binance", "contact": "ops@example.com", "meta": {"region":"eu"}, "producer_id": "uuid" }` (producer_id optional for key rotation)
  - `nonce`: random string (>=16 bytes)
  - `sig`: base64 signature over `SHA3-512(payload||"."||nonce)` using the corresponding `pubkey`'s private key

### Verification Steps (v2)
1. **Rate Limiting**: Check Redis rate limit (default 10 RPM per fingerprint), silent drop if exceeded.
2. Canonicalize `payload` JSON to a deterministic string; concatenate `payload + "." + nonce`.
3. Verify signature with the provided `pubkey` over that exact byte sequence.
4. Derive fingerprint (SHA3-512 over public key bytes, base64).
5. **State Machine Logic**:
   - **Case 1 (New Producer)**: Unknown fingerprint, no `producer_id` → create producer, key status=`pending`
   - **Case 2 (Key Rotation)**: Unknown fingerprint, WITH `producer_id` → validate existing producer, key status=`pending`
   - **Case 3 (Known Approved)**: Known fingerprint, status=`approved` → return existing `producer_id`
   - **Case 4 (Known Pending)**: Known fingerprint, status=`pending` → silent (no response)
   - **Case 5 (Known Denied)**: Known fingerprint, status=`revoked`/`superseded` → return denial
6. Create `producer_registrations` row with status `pending` and include the resolved `producer_id`.
7. Acknowledge after durable writes and publish a response to `fdc:register:resp:<nonce>` with `{ fingerprint, producer_id, status, reason? }` and set a short TTL on the stream.

### Admin Workflow (v2)
- **`/admin/review`** endpoint for approve/deny actions:
  - **Approve New Producer**: Creates producer and approves key atomically
  - **Approve Key Rotation**: Approves new key and supersedes old key atomically
  - **Deny Registration**: Marks key as revoked with reason
- **`/admin/pending`**: List pending registrations
- **`/admin/auth`**: List all producer keys and their statuses
- Admin can revoke tokens via `/admin/revoke`.
- Admin requests must be authenticated with OpenSSH certificates signed by a configured CA.

### Security Audit & Risks (v2)
- **Rate Limiting**: Kernel-side enforcement (default 10 RPM) prevents registration spam, silent drop on limit exceeded.
- **Replay Protection**: Nonce anti-replay with Redis `SETNX reg:nonce:<fp>:<nonce>` with 1h TTL.
- **Key Substitution**: Signature verifies against provided `pubkey`, binding requires admin approval; no auto-issue.
- **Token Exchange Abuse**: Only `approved` keys can exchange for tokens; rate limiting per fingerprint.
- **State Machine Security**: Strict validation with no fallbacks; every failure = hard rejection.
- **Atomic Key Rotation**: Old key superseded in same transaction as new key approved; no window with 0 or 2 approved keys.
- **DLQ Exposure**: Registration stream separate from data stream; no secrets in Redis.
- **Admin CA Verification**: SSH certificate validation with `X-SSH-Cert` and `X-SSH-Principal` headers.
- **Database Availability**: Auth/token gating requires Postgres reachability; spill-only mode rejects unauthenticated events.

### Future Hardening (v2)
- **Implemented**: Rate limiting, atomic key rotation, strict state machine validation
- **Implemented**: OpenSSH certificate verification for admin endpoints
- **Implemented**: Enhanced logging (INFO level for all access events)
- **Remaining**: Enforce unique `nonce` per fingerprint for a time window (DB unique constraint or Redis set with TTL)
- **Remaining**: Implement token-exchange rate limits per fingerprint and global caps
- **Remaining**: Enforce short TTL and auto-cleanup for `fdc:register:resp:<nonce>`

### Implementation Status (v2 - Complete)
- **Database**: Migration `0007_registration_v2.sql` with enhanced schema, atomic functions, and constraints
- **Configuration**: Rate limiting and response TTL settings added
- **Registration Flow**: Complete rewrite with state machine, rate limiting, and enhanced logging
- **Admin Endpoints**: `/admin/review` for approve/deny actions with atomic key rotation support
- **Token Exchange**: Enhanced validation requiring `approved` key status
- **Producer Example**: Updated to support optional `producer_id` for key rotation
- **Testing**: Integration tests updated for new flow
- **Documentation**: Protocol and registration docs updated with v2 enhancements
- **Security**: Rate limiting, atomic operations, strict validation, enhanced logging implemented

### Token Exchange (v2 - Enhanced)
- Stream: `fdc:token:exchange` (fixed); responses on `fdc:token:resp:<producer_id>`.
- Request may be authenticated by either:
  - a valid **approved** `pubkey` and signature over `payload + "." + nonce`, or
  - a still-valid short-lived token for renewal.
- **Key Status Validation**: Only keys with status=`approved` can exchange for tokens.
- Kernel issues a short-lived token when the fingerprint is approved and bound to the `producer_id` and returns `{ fingerprint, producer_id, token, exp }`.

### Deregistration
- Producers may send `{ action: "deregister", pubkey, payload, nonce, sig }` to `fdc:register`.
- On valid signature and known binding, the kernel sets `producers.disabled_at = now()` and responds on `fdc:register:resp:<nonce>` with `{ status: "deregistered" }`.
- While disabled, events from that `producer_id` are rejected (DLQ reason `producer_disabled`) until the next successful registration.

