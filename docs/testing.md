## Test Environment Overview

This document explains the test strategy, how to run tests, and how producers (collector modules) can validate protocol compliance.

### Layers
- Unit tests: validate core packages (`protocol`, `kernelcfg`, `sink`, `ws` behavior, `modulespec`).
- Integration tests: boot a kernel with a temporary config, exercise the WebSocket protocol, and assert NDJSON sink output. Optional backends (Postgres/Redis) are stubbed by configuration.
- Producer compliance tests: a harness that connects via WS and validates handshake, acks, and flow control for new modules (planned, see below).

### How to run
- Unit tests: `make test-unit`
- Integration tests: `make test-integration` (requires network loopback; starts kernel on a random localhost port)
- All tests: `make test`

### Temporary kernel harness
- `internal/testutil` provides `StartKernel(t, override)` which:
  - Allocates a free localhost port
  - Generates a unique auth token
  - Writes a temporary YAML config that enables the NDJSON file sink to a temp directory
  - Starts the kernel in the background and returns `ws://host:port/ws` and a `Close()` cleanup
- Tests can mutate the config via the `override` callback (e.g., enable Redis/Postgres, change limits).

### Protocol validation
- `internal/protocol` has shape validation for envelopes and helpers to build `ack`/`error` messages.
- WS server unit tests cover:
  - Auth required (missing token is rejected)
  - Optional hello/control message with `window_size`
  - Envelope validation path and returning `ack`

### Sink testing
- NDJSON sink tests validate rotation by size and gzip compression mode. Files are written to a temporary directory.

### Router and backends
- The router writes envelopes to the file sink and optionally to Redis and Postgres via bounded queues. Unit coverage is exercised indirectly; additional white-box router tests can be added if we export a constructor or use `//go:build`-gated test-only hooks.

### Producer compliance (upcoming)
- Provide a Go (or Python) test client that:
  - Connects to the kernel with an auth token
  - Validates server `hello` and `window_size`
  - Sends a battery of envelopes including boundary cases (max size, invalid types, wrong version)
  - Asserts correct `ack` behavior and error handling, and that flow control is respected
- This suite will live under `integration/producer/` with its own build tag and can be invoked with `make test-integration` or `go test -tags=integration ./integration/producer`.

### Contributing tests
- Place package unit tests next to the code (`*_test.go`). Prefer external test packages to avoid import cycles (e.g., `package kernel_test`).
- Use `internal/testutil` to spin up a kernel when end-to-end behavior is needed.
- Keep tests deterministic and time-bound. Use short deadlines and bounded queues.

### CI
- Recommended steps:
  - `go vet ./...`
  - `make test-unit`
  - `make test-integration`
- Artifacts: consider uploading NDJSON snapshots from integration tests for debugging.

