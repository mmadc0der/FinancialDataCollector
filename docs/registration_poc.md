## Producer Registration & Token Exchange - PoC and Security Audit

### Goals
- Automate producer onboarding while enforcing strict authentication.
- Remove producer-side optionality; use fixed Redis streams for requests and responses.
- Keep data-plane unencrypted but ensure only authenticated producers can write events.

### Design Overview (v2 - Enhanced Security)
- Redis registration stream `fdc:register` (fixed): producers submit signed requests.
- Responses are published to `fdc:register:resp:<nonce>` (per-request, ephemeral with TTL; kernel sets an expiry on this stream after emitting the response).
- OpenSSH-style public keys for producers are used to verify signatures and derive fingerprints.
- Postgres keeps:
  - `producer_keys(fingerprint, pubkey, status[pending|approved|revoked|superseded], producer_id NOT NULL, superseded_at)`
  - `producer_registrations(reg_id, fingerprint, payload, sig, nonce, ts, status[pending|approved|rejected], reviewer, reason)`
  - `producer_tokens` and `revoked_tokens` (from previous migration) remain authoritative for issuance/blacklist.
- **Enhanced Registration Flow**:
  - **New Producer**: Unknown fingerprint, no `producer_id` → creates producer, key status=`pending`
  - **Key Rotation**: Unknown fingerprint, WITH `producer_id` → validates existing producer, key status=`pending`
  - **Known Keys**: Returns existing status (approved/pending/denied)
- **Rate Limiting**: Kernel-side, distributed (Redis Lua token bucket) with per-op identity keys.
- **Admin API**: protected via mTLS and detached signature with OpenSSH admin certificate.

### Message Format (registration stream)
- XADD fields:
  - `pubkey`: OpenSSH public key (text)
  - `payload`: canonical JSON, e.g. `{ "producer_hint": "binance", "contact": "ops@example.com", "meta": {"region":"eu"}, "producer_id": "uuid" }`
  - `nonce`: random string (>=16 bytes)
  - `sig`: base64 signature over `canonical(payload)+"."+nonce` using the corresponding `pubkey`'s private key

### Verification Steps (v2)
1. **Rate Limiting**: Check distributed rate limiter; drop if exceeded.
2. Canonicalize `payload` JSON; concatenate `canonical(payload) + "." + nonce`.
3. Verify signature with provided `pubkey` over that exact byte sequence; unwrap SSH certificate to raw key if `producer_ssh_ca` is configured and matches.
4. Derive fingerprint (SHA3-512 over public key bytes, base64).
5. **State Machine Logic**:
   - **Case 1 (New Producer)**: Unknown fingerprint, no `producer_id` → create producer, key status=`pending`
   - **Case 2 (Key Rotation)**: Unknown fingerprint, WITH `producer_id` → validate existing producer, key status=`pending`
   - **Case 3 (Known Approved)**: Known fingerprint, status=`approved` → return existing `producer_id`
   - **Case 4 (Known Pending)**: Known fingerprint, status=`pending` → silent (no response)
   - **Case 5 (Known Denied)**: Known fingerprint, status=`revoked`/`superseded` → return denial
6. Create `producer_registrations` row and enforce DB uniqueness on `(fingerprint, nonce)`.
7. Acknowledge after durable writes and publish a response to `fdc:register:resp:<nonce>` with `{ fingerprint, producer_id, status, reason? }` and a short TTL.

### Admin Workflow (v2)
- **`/auth/review`** endpoint for approve/deny actions:
  - **Approve New Producer**: Creates producer and approves key atomically
  - **Approve Key Rotation**: Approves new key and supersedes old key atomically
  - **Deny Registration**: Marks key as revoked with reason
- Root `GET /auth`: View pending registrations
- Admin can revoke tokens via `POST /auth/revoke`.
- Admin requests must be authenticated with:
  - mTLS (client cert signed by Admin X.509 CA), and
  - Detached Ed25519 signature with OpenSSH admin certificate (`X-Admin-Cert`, `X-Admin-Nonce`, `X-Admin-Signature`) over `canonicalJSON(body)+"\n"+METHOD+"\n"+PATH+"\n"+nonce`.

### Security Audit & Risks (v2)
- **Rate Limiting**: Distributed token bucket prevents spam; metrics expose allow/deny by operation.
- **Replay Protection**: Redis `SETNX reg:nonce:<fp>:<nonce>` with 1h TTL, plus DB unique index on `(fingerprint, nonce)`.
- **Key Substitution**: Cert unwrapping checks CA; admin approval binds key to producer.
- **Token Exchange Abuse**: Only `approved` keys can exchange for tokens; distributed rate limits apply.
- **State Machine Security**: Strict validation; failures are hard rejections.
- **Atomic Key Rotation**: Old key superseded in same transaction as new key approved.
- **DLQ Exposure**: No secrets in Redis streams.
- **Admin CA Verification**: SSH certificate + principal checked; mTLS required.
- **Database Availability**: Control-plane requires Postgres reachability.

### Implementation Status (v2 - Complete)
- Database: baseline migrations enforce uniqueness and ingestion constraints.
- Configuration: TLS/mTLS and admin signing settings added.
- Registration Flow: canonical signing, rate limiting, and enhanced logging.
- Admin Endpoints: mTLS + detached signature; atomic key rotation.
- Token Exchange: requires `approved` key; canonical signing enforced.
- Producer Example: supports optional `producer_id` for key rotation.
- Testing: integration tests to be updated to enforce canonicalization and distributed rate limits.
- Observability: Security KPIs exported via Prometheus.

### Token Exchange (v2 - Enhanced)
- Stream: `fdc:token:exchange` (fixed); responses on `fdc:token:resp:<producer_id>`.
- Request may be authenticated by either:
  - a valid **approved** `pubkey` and signature over `canonical(payload) + "." + nonce`, or
  - a still-valid short-lived token for renewal.
- **Key Status Validation**: Only keys with status=`approved` can exchange for tokens.
- Kernel issues a short-lived token when the fingerprint is approved and bound to the `producer_id` and returns `{ fingerprint, producer_id, token, exp }`.

### Deregistration
- Producers may send `{ action: "deregister", pubkey, payload, nonce, sig }` to `fdc:register`.
- On valid signature and known binding, the kernel sets `producers.disabled_at = now()` and responds on `fdc:register:resp:<nonce>` with `{ status: "deregistered" }`.
- While disabled, events from that `producer_id` are rejected (DLQ reason `producer_disabled`) until the next successful registration.

