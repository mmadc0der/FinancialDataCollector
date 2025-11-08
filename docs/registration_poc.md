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

#### Admin Request Example (mTLS + detached signature)

1. **Prepare the review payload** (approve, deny, or revoke). Keep keys lowercase and omit optional fields you do not need:

   ```bash
   payload='{"action":"approve","producer_id":"<producer-uuid>","fingerprint":"<ssh-fingerprint>","notes":"initial onboarding"}'
   ```

2. **Canonicalize the JSON** exactly the way the kernel does (round-trip through a JSON parser). `jq -c -S` or `python -m json.tool` both work:

   ```bash
   canon_payload=$(echo "$payload" | jq -c -S .)
   ```

3. **Generate a unique nonce** (minimum 16 random bytes). The nonce is replay-protected for 5 minutes:

   ```bash
   nonce=$(openssl rand -hex 16)
   ```

4. **Build the string to sign**: `canonicalJSON + "\n" + METHOD + "\n" + PATH + "\n" + nonce` using uppercase HTTP method and the exact request path:

   ```bash
   signing_string=$(printf '%s\n%s\n%s\n%s' "$canon_payload" "POST" "/auth/review" "$nonce")
   printf '%s' "$signing_string" > /tmp/admin-signing.bin
   ```

5. **Sign with the admin Ed25519 private key** that was issued alongside the OpenSSH admin certificate. One option is to use Python + `cryptography` (ensures raw Ed25519 output):

   ```bash
   signature=$(python - <<'PY'
import base64, sys
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives import serialization

with open('/path/to/admin_ed25519', 'rb') as fh:
    key = load_ssh_private_key(fh.read(), password=None)

with open('/tmp/admin-signing.bin', 'rb') as fh:
    msg = fh.read()

sig = key.sign(msg)
print(base64.b64encode(sig).decode().strip())
PY
   )
   ```

   *Ensure the key is in OpenSSH format (`ssh-ed25519 ...`). If it is encrypted, supply the passphrase in `load_ssh_private_key`.*

6. **Flatten the OpenSSH admin certificate** (no newlines) for `X-Admin-Cert`:

   ```bash
   admin_cert=$(tr -d '\n' < /path/to/admin-cert.pub)
   ```

7. **Send the request** over mTLS. You can do this manually with `curl` or by using the helper script described below.

#### Admin Helper Script (`admin_request.py`)

To simplify MFA-secured requests, the repository ships with `scripts/admin_request.py`. It wraps payload canonicalization, nonce generation, signature creation, and HTTPS POST in one tool.

```bash
pip install cryptography requests
```

Example usage (approve or deny):

```bash
python scripts/admin_request.py request \
  --host kernel.example.com \
  --port 7600 \
  --payload '{"action":"approve","producer_id":"<uuid>","fingerprint":"<fp>","notes":"initial onboarding"}' \
  --prompt-passphrase
```

Helpful flags under the `request` subcommand:

- `--host` (required): kernel hostname/IP (scheme assumed `https`).
- `--payload`: JSON string or `@file.json`. Use `action=approve|deny|revoke`.
- `--path` / `--method`: override for `/auth` (GET) or `/auth/revoke`.
- `--port`: defaults to 443.
- `--mtls-cert` / `--mtls-key`: TLS client cert/key (defaults to `~/.ssh/admin-mtls*.pem`).
- `--admin-cert` / `--admin-key`: OpenSSH admin certificate and matching Ed25519 private key.
- `--prompt-passphrase`: securely prompt for the Ed25519 key passphrase when encrypted.
- `--nonce`: supply your own nonce; otherwise the script generates one.
- `--verify-ca`: path to CA bundle; defaults to system trust store.

There is also a `generate-csr` subcommand to produce a TLS private key + CSR:

```bash
python scripts/admin_request.py generate-csr \
  --output-cert ~/.ssh/admin-mtls.pem \
  --output-key ~/.ssh/admin-mtls-key.pem \
  --output-csr ~/.ssh/admin-mtls.csr \
  --subject "/CN=admin-ops" \
  --san DNS:admin-ops
```

`generate-csr` only produces the key and CSR. You must submit the CSR to the Admin X.509 CA and install the signed certificate at the `--output-cert` path before sending requests.

The TLS materials (`--mtls-cert`/`--mtls-key`) are standard X.509 artifacts used for the HTTPS handshake. The admin Ed25519 key and OpenSSH certificate (`--admin-key`/`--admin-cert`) are separate and power the detached signature headers. Both sets are required; the helper script aborts early if any file is missing and explains how to generate/request the missing piece.

The script prints the HTTP status and any JSON response from the kernel. `200`/`201` include body content (approved/denied info). `204` is success without body (e.g., token revoke). `401`, `400`, or `500` indicate authentication/validation/persistence errors—inspect kernel logs for root cause.

This automated path replaces the legacy `X-SSH-Certificate` header: every admin request must now use mTLS, send `X-Admin-Cert` with the OpenSSH certificate, and supply the detached Ed25519 signature as described.

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

