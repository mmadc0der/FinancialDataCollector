## Kernel ↔ Module Protocol

Version: 0.1.0 (DRAFT)

### Transport
- Data-plane: Redis Streams. Modules publish to `events` with XADD. Fields:
  - `payload`: the envelope JSON
  - `token`: producer auth token (required when auth is enabled)
  Kernel consumes with XREADGROUP and acknowledges after durable write (Postgres or spill).

### Envelope
```json
{
  "version": "0.1.0",
  "type": "data|heartbeat|control|ack|error",
  "id": "01J9Z0MZ3D0J3C3N8C4E9W6Z7Q",
  "ts": 1727200000000000,
  "data": { /* payload */ }
}
```
### Data payloads
- type=data: `kind` field defines event schema.
```json
{
  "kind": "trade|quote|orderbook|ohlc|status",
  "source": "binance",
  "symbol": "BTCUSDT",
  "seq": 123456789,
  "ts_event": 1727200000000000,
  "ts_collector": 1727200000000100,
  "payload": { /* kind-specific */ },
  "meta": { "module_version": "1.2.3" }
}
```

### Heartbeats
- Not used by the kernel; modules may implement their own health mechanisms.

### Flow control
- Redis provides buffering. Modules may set `MAXLEN ~` on XADD to cap stream length.
- Kernel acknowledges only after durable persistence (Postgres commit) or successful spill write.
 - Unauthenticated or invalid messages are written to DLQ with reason `unauthenticated`.

### Errors
- Kernel may return type=error with `code` and `message`. Fatal errors lead to connection close.

### Control
- No control-plane from kernel. Modules are decoupled and only push data to Redis.

### Limits
- Max message size: configurable (default 1 MiB).
- Stream trimming: approximate via Redis `MAXLEN ~` when publishing.
- No built-in rate limiting in the kernel; producers should self-throttle as needed.

### Authentication (optional)
- Minimal signed tokens (Ed25519) are supported. Tokens bind to a specific `producer_id` and carry `iss`, `aud`, `exp`, `nbf`, `jti` claims. The kernel validates signature and checks `jti` against the allowlist/blacklist in Postgres. A Redis cache accelerates validation.
- Include the token via XADD field `token`. Without a valid token, the message is rejected.

### Registration and Refresh (optional)
- Producers can request registration or token refresh by publishing to `fdc:register` (configurable) with fields:
  - `pubkey`: OpenSSH public key (text)
  - `payload`: canonical JSON string (RFC8785 or sorted-keys compact form)
  - `nonce`: random string
  - `sig`: base64 signature over `payload + "." + nonce` using the provided `pubkey` (payload must be canonicalized)
 - If the `pubkey` fingerprint is already approved and bound to a known `producer_id`, the kernel can auto-issue a token.
- Otherwise, the request is stored as pending for administrator review.
 - Admin flow: `GET /admin/pending` for list, `POST /admin/approve` binds key, creates a `producer` if needed (UUIDv4 generated SQL-side), and issues a token.
 - Optional response stream: if configured, kernel publishes `{fingerprint, token}` to `register_resp_stream` on auto-issue.
 - Anti-replay: nonces are cached with TTL; duplicate nonces are rejected.

