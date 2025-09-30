## Verification Pipeline

### Goals
- Validate protocol compliance and resilience under module misbehavior.
- Verify data quality at per-second cadence with high event throughput.
- Ensure reproducible builds and deterministic kernel behavior.

### Layers
1. Static checks: lint, format, schema generation and validation for messages.
2. Unit tests: kernel components (config, logging, supervisor, ws server, sinks).
3. Integration tests: spin up kernel, launch example module, assert protocol handshakes, acks, flow control.
4. Fault-injection tests: simulate slow sink, message bursts, oversized messages, protocol violations, crashes.
5. End-to-end snapshot: record NDJSON output, validate against JSON Schemas and invariants (monotonic seq, timestamps ordering, required fields).

### Tooling
- Go test with race detector, coverage.
- JSON Schema validation via `github.com/santhosh-tekuri/jsonschema/v5`.
- Python module tests with `pytest` (for example module).
- Benchmarks with `go test -bench` and synthetic generators.

### CI stages
1. Build: `go build ./...` and `python -m pyflakes` for example.
2. Lint: `golangci-lint run` (optional if allowed), `go vet ./...`.
3. Unit tests: `go test -race -cover ./...`.
4. Integration: start kernel in background, run example module, assert outputs.
5. Artifacts: upload NDJSON snapshots and logs.

### Determinism & Seeds
- Use fixed seeds for synthetic generators. Freeze time in tests where possible.

### Performance Gates
- Minimum throughput: 10k msgs/min sustained in local env.
- Max p99 ingest latency: < 50ms with file sink enabled.

