## Logging System

### Overview

The kernel uses an **event-driven, security-compliant logging framework** that provides structured, asynchronous logging with bounded memory and automatic severity level assignment. All logs are JSON-structured and designed to meet international security requirements for authentication and authorization events.

### Goals

- **Event-driven architecture**: Structured event schemas for different event types (API access, authentication, registration, tokens, admin actions, infrastructure)
- **Security compliance**: All authentication and authorization events are logged with appropriate severity levels
- **Asynchronous, non-blocking**: Bounded channel-based logging to avoid backpressure on hot paths
- **JSON structured logs**: Low overhead, minimal allocations, easy to parse and analyze
- **Proper severity levels**: Automatic assignment based on event type and outcome (DEBUG/INFO/WARN/ERROR)

### Architecture

#### Core Components

1. **Event Logger**: Provides structured event logging methods (`APIAccess`, `Auth`, `Registration`, `Token`, `Admin`, `Infra`)
2. **Asynchronous Drain**: Single background goroutine drains a bounded channel and writes to an `io.Writer` (stdout by default)
3. **Dropped Log Counter**: Tracks dropped logs when channel is full to avoid backpressure

#### Log Format

Each log entry follows this structure:
```json
{
  "ts": 1234567890000000000,
  "level": "info",
  "msg": "api_access",
  "fields": {
    "event": "api-access",
    "action": "post",
    "from": "192.168.1.1",
    "subject": "admin@example.com",
    "object": "/auth/review",
    "status": "success",
    "http_code": 200
  }
}
```

### Configuration

```yaml
logging:
  level: "info"        # debug|info|warn|error (minimum log level)
  buffer: 4096         # channel size (bounded memory)
  output: "stdout"     # stdout|stderr|<file path>
```

### Event Schemas

The logging system provides structured event types for different scenarios:

#### 1. API Access Events (`APIAccess`)

Logs all HTTP API access attempts with subject, object, and outcome.

**Fields:**
- `event`: "api-access"
- `action`: HTTP method (get|post|put|delete|patch|head|options)
- `from`: Remote IP address
- `subject`: Authenticated principal (if available)
- `object`: Request path
- `status`: "success" | "failed"
- `reason`: Error reason (if failed)
- `http_code`: HTTP status code

**Severity:**
- `success`: DEBUG
- `failed` (4xx): WARN
- `failed` (5xx): ERROR

**Example:**
```go
ev := logging.NewEventLogger()
ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), principal, r.URL.Path, "success", "", http.StatusOK)
```

#### 2. Authentication Events (`Auth`)

Logs all authentication attempts, successes, and failures. **Required for security compliance.**

**Fields:**
- `event`: "auth"
- `component`: "auth"
- `stage`: Always `authentication`
- `action`: Normalized verb (for example: `login`, `logout`, `verify`, `failure`)
- `outcome`: `success` | `failed`
- `subject` *(optional)*: Authenticated principal (SSH certificate principal, producer ID, etc.)
- `ip` *(optional)*: Remote IP address
- `reason_code` *(optional)*: Normalized error code (derived from `reason` argument)
- `details` *(optional)*: Free-form context extracted from the `reason`

**Severity:**
- `outcome=success`: INFO
- `outcome=failed`: WARN
- `action=failure` and `outcome=failed`: ERROR

**Example:**
```go
ev := logging.NewEventLogger()
ev.Auth("verify", principal, logging.RemoteAddr(r), true, "")
ev.Auth("failure", "", logging.RemoteAddr(r), false, "certificate_expired")
```

#### 3. Authorization Events (`Authorization`)

Logs authorization decisions (allow/deny). **Required for security compliance.**

**Fields:**
- `event`: "authorization"
- `action`: "allow" | "deny"
- `subject`: Principal making request
- `object`: Resource being accessed
- `reason`: Denial reason (if denied)

**Severity:**
- `allow`: INFO
- `deny`: WARN

**Example:**
```go
ev := logging.NewEventLogger()
ev.Authorization("deny", principal, "/admin/revoke", "insufficient_privileges")
```

#### 4. Registration Events (`Registration`)

Logs producer key onboarding, subject registration, schema upgrades, and security violations.

**Fields (core):**
- `event`: "registration"
- `component`: "registration"
- `stage`: Workflow segment (for example `request`, `request_validation`, `payload_validation`, `nonce_guard`, `certificate_validation`, `signature_verification`, `status`, `registration`)
- `action`: Normalized action token such as:
  - `message_received`, `message_invalid`
  - `payload_invalid`
  - `rate_limited`
  - `nonce_replay`
  - `certificate_invalid`
  - `signature_invalid`
  - `status_check`, `status_pending`, `status_denied`, `status_unknown`, `status_approved`
  - `deregister_request`, `deregistered`
  - `success`
- `outcome`: `attempt` | `success` | `failed` | `denied` | `pending`

**Additional fields (when available):**
- `fingerprint`: SSH key fingerprint
- `producer_id`: Producer UUID
- `subject_id`: Subject UUID (for subject flows)
- `status`: Raw status returned by upstream systems (only when it differs from `outcome`)
- `reason_code` / `details`: Structured reason extracted from the call-site `reason`

**Severity:**
- `outcome=attempt` | `pending`: INFO (visibility into live registration traffic)
- `outcome=success`: INFO
- `outcome=denied` | `failed`: WARN

**Example:**
```go
ev := logging.NewEventLogger()
ev.Registration("message_received", fingerprint, "", "attempt", "received: action=register nonce=123")
ev.Registration("certificate_invalid", fingerprint, producerID, "failed", "certificate_verification_failed")
ev.Registration("success", fingerprint, producerID, "success", "completed: op=register schema=customers")
```

#### 5. Token Events (`Token`)

Logs token lifecycle events (issuance, exchange, revocation, verification).

**Fields:**
- `event`: "token"
- `component`: "auth"
- `stage`: `token_issue` | `token_exchange` | `token_revoke` | `token_verify`
- `action`: Normalized action (for example `issue`, `exchange`, `revoke`, `verify`)
- `outcome`: `success` | `failed`
- `producer_id`, `subject_id`, `jti` *(optional)*
- `status`: Present only when the caller supplies an explicit status value distinct from `outcome`
- `reason_code` / `details`: Included on failures

**Severity:**
- `action=verify` and `outcome=success`: DEBUG (to avoid log spam)
- Other `outcome=success`: INFO
- `outcome=failed`: WARN

**Example:**
```go
ev := logging.NewEventLogger()
ev.Token("issue", producerID, "", jti, true, "")
ev.Token("verify", producerID, subjectID, jti, false, "token_expired")
```

#### 6. Admin Events (`Admin`)

Logs all administrative actions. **Required for security compliance.**

**Fields:**
- `event`: "admin"
- `action`: "review" | "approve" | "deny" | "revoke" | "access"
- `admin_principal`: Admin SSH certificate principal
- `target`: Target resource (producer ID, JTI, etc.)
- `status`: "success" | "failed"
- `reason`: Action reason

**Severity:**
- `success`: INFO (always logged - security requirement)
- `failed`: ERROR

**Example:**
```go
ev := logging.NewEventLogger()
ev.Admin("approve", adminPrincipal, producerID, "manual_review", true)
ev.Admin("revoke", adminPrincipal, jti, "security_incident", true)
```

#### 7. Infrastructure Events (`Infra`)

Logs infrastructure operations (database connections, Redis operations, spill writes, etc.).

**Fields:**
- `event`: "infra"
- `component`: Normalized component name (for example `redis`, `postgres`, `kernel`, `spill`)
- `stage`: Derived from component/action (for example `redis_read`, `postgres_write`, `kernel_start`)
- `action`: Normalized action such as `start`, `config`, `init`, `connect`, `disconnect`, `read`, `write`, `ack`, `retry`, `error`
- `outcome`: `success` | `failed` | `retry` | `denied` | `skipped`
- `status`: Raw status when supplied by the caller and different from `outcome`
- `details`: Free-form context message

**Severity:**
- `outcome=success` for startup/config actions: INFO
- `outcome=success` for steady-state operations: DEBUG
- `outcome=retry` | `outcome=denied` | `outcome=skipped`: WARN
- `outcome=failed`: ERROR

**Example:**
```go
ev := logging.NewEventLogger()
ev.Infra("write", "postgres", "success", fmt.Sprintf("batch commit: batch_size=%d", len(events)))
ev.Infra("error", "redis", "failed", fmt.Sprintf("stream read error: %v", err))
```

### Usage

#### Creating an Event Logger

```go
import "github.com/example/data-kernel/internal/logging"

// Create a new event logger instance
ev := logging.NewEventLogger()
```

#### Logging API Access

```go
ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), principal, r.URL.Path, "success", "", http.StatusOK)
ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), "", r.URL.Path, "failed", "unauthorized", http.StatusUnauthorized)
```

#### Logging Authentication Events

```go
// Successful authentication
ev.Auth("verify", principal, logging.RemoteAddr(r), true, "")

// Failed authentication
ev.Auth("failure", "", logging.RemoteAddr(r), false, "certificate_expired")
```

#### Logging Registration Events

```go
// Inbound registration message
ev.Registration("message_received", fingerprint, "", "attempt", "received: action=register nonce=abc123")

// Certificate validation failure
ev.Registration("certificate_invalid", fingerprint, producerID, "failed", "certificate_verification_failed")

// Successful registration (subject/schema assign)
ev.Registration("success", fingerprint, producerID, "success", "completed: op=register schema=customers")
```

#### Logging Token Events

```go
// Token issuance
ev.Token("issue", producerID, "", jti, true, "")

// Token verification failure
ev.Token("verify", producerID, subjectID, jti, false, "token_expired")
```

#### Logging Admin Actions

```go
// Admin approval
ev.Admin("approve", adminPrincipal, producerID, "manual_review", true)

// Admin token revocation
ev.Admin("revoke", adminPrincipal, jti, "security_incident", true)
```

#### Logging Infrastructure Events

```go
// Database batch commit
ev.Infra("write", "postgres", "success", fmt.Sprintf("batch commit: batch_size=%d", len(events)))

// Redis connection error
ev.Infra("error", "redis", "failed", fmt.Sprintf("connection failed: %v", err))

// Circuit breaker open
ev.Infra("error", "postgres", "failed", fmt.Sprintf("circuit breaker open: batch_size=%d", len(events)))
```

### Performance

- **Single allocation per field** where possible
- **Bounded memory**: Channel size limits memory usage
- **Non-blocking**: Dropped logs are counted instead of blocking
- **Dropped log count**: Reported periodically at `warn` level

### Security Compliance

The logging system is designed to meet international security requirements:

1. **Authentication Logging**: All authentication attempts (successful and failed) are logged with appropriate severity
2. **Authorization Logging**: All authorization decisions are logged
3. **Admin Action Logging**: All administrative actions are logged at INFO level or higher
4. **Structured Format**: JSON format enables easy parsing and analysis in SIEM systems
5. **Event Classification**: Events are classified by type for easy filtering and analysis

### Log Analysis

#### Filtering by Event Type

```bash
# Extract all authentication events
jq 'select(.fields.event == "auth")' < logs.jsonl

# Extract all failed authentication attempts
jq 'select(.fields.event == "auth" and .fields.status == "failed")' < logs.jsonl

# Extract all admin actions
jq 'select(.fields.event == "admin")' < logs.jsonl

# Extract all API access failures
jq 'select(.fields.event == "api-access" and .fields.status == "failed")' < logs.jsonl
```

#### Common Queries

```bash
# Failed authentication attempts by IP
jq -r 'select(.fields.event == "auth" and .fields.status == "failed") | "\(.fields.ip) - \(.fields.reason)"' < logs.jsonl | sort | uniq -c

# Admin actions by principal
jq -r 'select(.fields.event == "admin") | "\(.fields.admin_principal) - \(.fields.action) - \(.fields.target)"' < logs.jsonl

# Registration rejections with reasons
jq 'select(.fields.event == "registration" and .fields.action == "reject")' < logs.jsonl
```

### Migration from Legacy Logging

The legacy `logging.Info`, `logging.Warn`, `logging.Error`, and `logging.Debug` methods are deprecated. All code has been migrated to use the event-driven system:

- **Infrastructure events** → `ev.Infra(action, component, status, details)`
- **API access** → `ev.APIAccess(method, from, subject, object, status, reason, httpCode)`
- **Authentication** → `ev.Auth(action, subject, ip, success, reason)`
- **Authorization** → `ev.Authorization(action, subject, object, reason)`
- **Registration** → `ev.Registration(action, fingerprint, producerID, subjectID, status, reason)`
- **Token operations** → `ev.Token(action, producerID, subjectID, jti, success, reason)`
- **Admin actions** → `ev.Admin(action, adminPrincipal, target, reason, success)`

### Tips

- **Always use structured events**: Use the appropriate event method instead of generic logging
- **Include context**: Provide relevant IDs (producer_id, jti, fingerprint) for traceability
- **Security events**: Authentication and authorization events are always logged at appropriate levels
- **Infrastructure errors**: All infrastructure failures are logged as ERROR level
- **Dropped logs**: Monitor the `logs_dropped` event to detect logging backpressure
