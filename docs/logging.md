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
- `action`: "login" | "logout" | "verify" | "failure"
- `subject`: Authenticated principal (SSH certificate principal, producer ID, etc.)
- `ip`: Remote IP address
- `status`: "success" | "failed"
- `reason`: Failure reason (if failed)

**Severity:**
- `success`: DEBUG
- `failed`: WARN
- `failure` action: ERROR

**Example:**
```go
ev := logging.NewEventLogger()
ev.Auth("verify", principal, logging.RemoteAddr(r), true, "")
ev.Auth("failure", "", logging.RemoteAddr(r), false, "certificate expired")
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

Logs producer registration attempts, approvals, rejections, and security violations.

**Fields:**
- `event`: "registration"
- `action`: "attempt" | "approve" | "reject" | "replay" | "invalid_cert" | "invalid_sig" | "rate_limited" | "success" | "error"
- `fingerprint`: SSH key fingerprint
- `producer_id`: Producer UUID (if available)
- `subject_id`: Subject ID (for subject registration)
- `status`: Registration status
- `reason`: Action reason

**Severity:**
- `attempt`: DEBUG
- `approve`: INFO (security event)
- `reject` | `replay` | `invalid_cert` | `invalid_sig` | `rate_limited`: WARN
- `error`: ERROR

**Example:**
```go
ev := logging.NewEventLogger()
ev.Registration("invalid_cert", fingerprint, producerID, "", "certificate_expired", "certificate expired")
ev.Registration("success", fingerprint, producerID, subjectID, "success", "registration completed")
```

#### 5. Token Events (`Token`)

Logs token lifecycle events (issuance, exchange, revocation, verification).

**Fields:**
- `event`: "token"
- `action`: "issue" | "exchange" | "revoke" | "verify"
- `producer_id`: Producer UUID
- `subject_id`: Subject ID (if applicable)
- `jti`: JWT ID (JTI)
- `status`: "success" | "failed"
- `reason`: Failure reason (if failed)

**Severity:**
- `success` (verify): DEBUG
- `success` (other): INFO
- `failed`: WARN

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
- `action`: "connect" | "disconnect" | "read" | "write" | "ack" | "init" | "migrate" | "error" | "retry" | "start" | "config"
- `component`: "redis" | "postgres" | "spill" | "kernel" | "auth" | "http"
- `status`: "success" | "failed"
- `details`: Detailed message

**Severity:**
- `success` (connect/disconnect): DEBUG
- `success` (other): INFO
- `failed` | `error`: ERROR
- `retry`: WARN

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
// Registration attempt
ev.Registration("attempt", fingerprint, "", "", "pending", "")

// Invalid certificate
ev.Registration("invalid_cert", fingerprint, producerID, "", "invalid_cert", "certificate expired")

// Successful registration
ev.Registration("success", fingerprint, producerID, subjectID, "success", "")
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
