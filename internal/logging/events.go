package logging

import (
	"net/http"
	"strings"
)

// EventLogger provides structured event logging with security-compliant schemas
type EventLogger struct {
	log func(level Level, msg string, fields ...Field)
}

// --- helpers to map legacy inputs to minimal schema ---
func mapRegStage(action string) string {
    switch strings.ToLower(action) {
    case "invalid_cert":
        return "certificate_validation"
    case "invalid_sig":
        return "signature_verification"
    case "replay":
        return "nonce_check"
    case "approve", "reject":
        return "approval_decision"
    case "rate_limited":
        return "rate_limit"
    case "success":
        return "registration"
    default:
        Error("infra", F("event", "infra"), F("component", "logging"), F("stage", "mapping"), F("action", "map_reg_stage"), F("outcome", "failed"), F("reason_code", "unknown_action"), F("details", "action="+action))
        return "request"
    }
}

func mapRegVerb(action string) string {
    switch strings.ToLower(action) {
    case "invalid_cert":
        return "validate"
    case "invalid_sig":
        return "verify"
    case "replay":
        return "check"
    case "approve":
        return "approve"
    case "reject":
        return "reject"
    case "rate_limited":
        return "throttle"
    case "success":
        return "register"
    case "attempt":
        return "request"
    default:
        Error("infra", F("event", "infra"), F("component", "logging"), F("stage", "mapping"), F("action", "map_reg_verb"), F("outcome", "failed"), F("reason_code", "unknown_action"), F("details", "action="+action))
        return strings.ToLower(action)
    }
}

func mapRegOutcome(action, status string) string {
    a := strings.ToLower(action)
    s := strings.ToLower(status)
    if a == "attempt" { return "attempt" }
    if a == "approve" || a == "success" || s == "approved" || s == "success" { return "success" }
    if a == "rate_limited" { return "denied" }
    if a == "replay" || a == "invalid_cert" || a == "invalid_sig" || a == "invalid" || a == "error" { return "failed" }
    if s == "pending" || s == "deregister" || s == "deregistered" { return "skipped" }
    Error("infra", F("event", "infra"), F("component", "logging"), F("stage", "mapping"), F("action", "map_reg_outcome"), F("outcome", "failed"), F("reason_code", "unknown_outcome_mapping"), F("details", "action="+action+",status="+status))
    return "failed"
}

func mapTokenStage(action string) string {
    switch strings.ToLower(action) {
    case "issue":
        return "token_issue"
    case "exchange":
        return "token_exchange"
    case "revoke":
        return "token_revoke"
    case "verify":
        return "token_verify"
    default:
        Error("infra", F("event", "infra"), F("component", "logging"), F("stage", "mapping"), F("action", "map_token_stage"), F("outcome", "failed"), F("reason_code", "unknown_action"), F("details", "action="+action))
        return "token"
    }
}

func mapAdminStage(action string) string {
    switch strings.ToLower(action) {
    case "review", "approve", "deny":
        return "approval_decision"
    case "revoke":
        return "revocation"
    case "access":
        return "access"
    default:
        Error("infra", F("event", "infra"), F("component", "logging"), F("stage", "mapping"), F("action", "map_admin_stage"), F("outcome", "failed"), F("reason_code", "unknown_action"), F("details", "action="+action))
        return "admin"
    }
}

func mapInfraStage(action string) string {
    switch strings.ToLower(action) {
    case "connect", "disconnect":
        return "connection"
    case "read", "write", "ack":
        return "io"
    case "retry":
        return "recovery"
    case "start", "config", "init", "migrate":
        return "initialization"
    case "error":
        return "processing"
    default:
        Error("infra", F("event", "infra"), F("component", "logging"), F("stage", "mapping"), F("action", "map_infra_stage"), F("outcome", "failed"), F("reason_code", "unknown_action"), F("details", "action="+action))
        return strings.ToLower(action)
    }
}

func mapInfraOutcome(status string) string {
    switch strings.ToLower(status) {
    case "success":
        return "success"
    case "failed":
        return "failed"
    case "empty":
        return "skipped"
    default:
        Error("infra", F("event", "infra"), F("component", "logging"), F("stage", "mapping"), F("action", "map_infra_outcome"), F("outcome", "failed"), F("reason_code", "unknown_status"), F("details", "status="+status))
        return strings.ToLower(status)
    }
}

func httpStatusStr(code int) string {
    if code == 0 { return "" }
    return "http=" + strings.TrimSpace(strings.ToLower(http.StatusText(code)))
}

// NewEventLogger creates a new EventLogger backed by the global logging functions
func NewEventLogger() *EventLogger {
	return &EventLogger{
		log: log,
	}
}

// APIAccess logs API access events with event+action framework
// action: get|post|put|delete|patch|head|options
// status: success|failed
func (e *EventLogger) APIAccess(action, from, subject, object, status, reason string, httpCode int) {
    // Minimal schema: event, component, stage, action, outcome, reason_code, details(optional)
    level := InfoLevel
    if status == "failed" {
        if httpCode >= 500 { level = ErrorLevel } else if httpCode >= 400 { level = WarnLevel }
    } else if status == "success" {
        level = DebugLevel // successful API calls are noisy; keep at debug
    }

    outcome := status
    if outcome == "" { outcome = "success" }
    fields := []Field{
        F("event", "api"),
        F("component", "api"),
        F("stage", "request"),
        F("action", strings.ToLower(action)),
        F("outcome", outcome),
    }
    if reason != "" { fields = append(fields, F("reason_code", reason)) }
    // Optional, compact details only if helpful
    if object != "" || httpCode != 0 { fields = append(fields, F("details", strings.Trim(strings.Join([]string{object, httpStatusStr(httpCode)}, " "), " "))) }
    e.log(level, "api", fields...)
}

// Auth logs authentication events
// action: login|logout|verify|failure
func (e *EventLogger) Auth(action, subject, ip string, success bool, reason string) {
    level := InfoLevel
    if success { level = DebugLevel } else { if action == "failure" { level = ErrorLevel } else { level = WarnLevel } }
    outcome := "success"; if !success { outcome = "failed" }
    fields := []Field{
        F("event", "auth"),
        F("component", "auth"),
        F("stage", "authentication"),
        F("action", strings.ToLower(action)),
        F("outcome", outcome),
    }
    if reason != "" { fields = append(fields, F("reason_code", reason)) }
    e.log(level, "auth", fields...)
}

// Authorization logs authorization events
// action: allow|deny
func (e *EventLogger) Authorization(action, subject, object, reason string) {
    level := InfoLevel
    outcome := "success"
    if action == "deny" { level = WarnLevel; outcome = "denied" }
    fields := []Field{
        F("event", "authorization"),
        F("component", "auth"),
        F("stage", "authorization"),
        F("action", strings.ToLower(action)),
        F("outcome", outcome),
    }
    if reason != "" { fields = append(fields, F("reason_code", reason)) }
    e.log(level, "authorization", fields...)
}

// Registration logs registration events
// action: attempt|approve|reject|replay|invalid_cert|invalid_sig|rate_limited
func (e *EventLogger) Registration(action, fingerprint, producerID, status, reason string) {
    // Map legacy action/status into minimal schema
    stage := mapRegStage(action)
    verb := mapRegVerb(action)
    outcome := mapRegOutcome(action, status)
    level := InfoLevel
    switch outcome {
    case "attempt", "skipped":
        level = DebugLevel
    case "success":
        level = InfoLevel
    default:
        level = WarnLevel
    }
    fields := []Field{
        F("event", "registration"),
        F("component", "registration"),
        F("stage", stage),
        F("action", verb),
        F("outcome", outcome),
    }
    if reason != "" { fields = append(fields, F("reason_code", reason)) } else if action != "" { fields = append(fields, F("reason_code", action)) }
    e.log(level, "registration", fields...)
}

// Token logs token lifecycle events
// action: issue|exchange|revoke|verify
func (e *EventLogger) Token(action, producerID, subjectID, jti string, success bool, reason string) {
    // Minimal schema, map to stage/action/outcome
    stage := mapTokenStage(action)
    outcome := "success"; if !success { outcome = "failed" }
    level := InfoLevel
    if action == "verify" && success { level = DebugLevel } else if !success { level = WarnLevel } else { level = InfoLevel }
    fields := []Field{
        F("event", "token"),
        F("component", "auth"),
        F("stage", stage),
        F("action", strings.ToLower(action)),
        F("outcome", outcome),
    }
    if reason != "" { fields = append(fields, F("reason_code", reason)) }
    e.log(level, "token", fields...)
}

// Admin logs admin action events
// action: review|approve|deny|revoke|access
func (e *EventLogger) Admin(action, adminPrincipal, target, reason string, success bool) {
    level := InfoLevel
    if !success { level = ErrorLevel }
    outcome := "success"; if !success { outcome = "failed" }
    fields := []Field{
        F("event", "admin"),
        F("component", "admin"),
        F("stage", mapAdminStage(action)),
        F("action", strings.ToLower(action)),
        F("outcome", outcome),
    }
    if reason != "" { fields = append(fields, F("reason_code", reason)) }
    e.log(level, "admin", fields...)
}

// Infra logs infrastructure events
// action: connect|disconnect|error|retry|read|write|ack|start|config|init|migrate
// component: redis|postgres|http
// status: success|failed|empty
func (e *EventLogger) Infra(action, component, status, details string) {
    // Map to minimal schema
    outcome := mapInfraOutcome(status)
    stage := mapInfraStage(action)
    level := DebugLevel
    switch outcome {
    case "failed":
        level = ErrorLevel
    case "skipped":
        level = WarnLevel
    case "success":
        if action == "start" || action == "config" || action == "init" || action == "migrate" { level = InfoLevel } else { level = DebugLevel }
    }
    fields := []Field{
        F("event", "infra"),
        F("component", component),
        F("stage", stage),
        F("action", strings.ToLower(action)),
        F("outcome", outcome),
    }
    if details != "" { fields = append(fields, F("details", details)) }
    e.log(level, "infra", fields...)
}

// Helper function to extract HTTP method from request
func HTTPMethod(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.ToLower(r.Method)
}

// Helper function to extract remote address (handles proxies)
func RemoteAddr(r *http.Request) string {
	if r == nil {
		return ""
	}
	// Check X-Forwarded-For header for proxy cases
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take first IP if multiple
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	return r.RemoteAddr
}

