## Kernel ↔ Module Protocol

Version: 0.1.0 (DRAFT)

### Transport
- Data-plane: Redis Streams. Modules publish to `events` with XADD (fields include `payload` as the envelope JSON). Kernel consumes with XREADGROUP and acknowledges after durable write (Postgres or spill).

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

### Errors
- Kernel may return type=error with `code` and `message`. Fatal errors lead to connection close.

### Control
- No control-plane from kernel. Modules are decoupled and only push data to Redis.

### Limits
- Max message size: configurable (default 1 MiB).
- Stream trimming: approximate via Redis `MAXLEN ~` when publishing.
- No built-in rate limiting in the kernel; producers should self-throttle as needed.

