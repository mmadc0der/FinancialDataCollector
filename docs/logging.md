## Logging System

### Goals
- Asynchronous, non-blocking logging with bounded memory.
- JSON structured logs; low overhead; minimal allocations.
- Global logger usable across packages.

### Design
- A single background goroutine drains a bounded channel and writes to an `io.Writer` (stdout by default).
- When the channel is full, logs are dropped with a counter to avoid backpressure on hot paths.
- Each log entry: `ts`, `level`, `msg`, `fields` map.

### Configuration

```yaml
logging:
  level: "info"        # debug|info|warn|error
  buffer: 4096         # channel size
  output: "stdout"     # stdout|stderr|<file path>
```

### Usage
- Use `logging.Info("started", logging.F("listen", cfg.Server.Listen))`.
- For errors: `logging.Error("db connect failed", logging.Err(err))`.

### Performance
- Single allocation per field where possible.
- Dropped log count reported periodically at `warn` level.

### Tips
- Include message ids and stream offsets when debugging Redis ingest.
- Record DLQ reasons for troubleshooting (`events:dlq`).

