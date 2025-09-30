## Kernel ↔ Module Protocol

Version: 0.1.0 (DRAFT)

### Transport
- WebSocket over TCP. Optional TLS termination in front proxy. Default: ws://127.0.0.1:7600
- One connection per module instance. Modules authenticate with static token from config.

### Envelope
```
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
```
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
- Module sends heartbeat every `heartbeat_interval_ms`. Kernel replies with `ack` containing last seen id and server time.

### Flow control
- Windowed acking: Kernel advertises `window_size`. Module may have up to `window_size` unacked messages. Acks may cover ranges via `last_id`.

### Errors
- Kernel may return type=error with `code` and `message`. Fatal errors lead to connection close.

### Control
- Kernel may send `control` messages: `pause`, `resume`, `reload`, `shutdown`. Modules must respond with `ack` and state.

### Limits
- Max message size: configurable (default 1 MiB). Max send rate: configurable (msgs/sec), enforced with 429-like errors.

