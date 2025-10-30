package logging

import (
	"net/http"
	"strings"
)

// EventLogger provides structured event logging with security-compliant schemas
type EventLogger struct {
	log func(level Level, msg string, fields ...Field)
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
	level := InfoLevel
	if status == "failed" {
		if httpCode >= 500 {
			level = ErrorLevel
		} else if httpCode >= 400 {
			level = WarnLevel
		}
	} else if status == "success" {
		level = DebugLevel // Successful API calls are DEBUG
	}
	
	fields := []Field{
		F("event", "api-access"),
		F("action", strings.ToLower(action)),
		F("object", object),
		F("status", status),
		F("http_code", httpCode),
	}
	if from != "" {
		fields = append(fields, F("from", from))
	}
	if subject != "" {
		fields = append(fields, F("subject", subject))
	}
	if reason != "" {
		fields = append(fields, F("reason", reason))
	}
	e.log(level, "api_access", fields...)
}

// Auth logs authentication events
// action: login|logout|verify|failure
func (e *EventLogger) Auth(action, subject, ip string, success bool, reason string) {
	level := InfoLevel
	if !success {
		level = WarnLevel // Failed auth attempts are WARN
		if action == "failure" {
			level = ErrorLevel // Explicit failures are ERROR
		}
	} else {
		level = DebugLevel // Successful auth can be DEBUG
	}
	
	status := "success"
	if !success {
		status = "failed"
	}
	
	fields := []Field{
		F("event", "auth"),
		F("action", action),
		F("status", status),
	}
	if subject != "" {
		fields = append(fields, F("subject", subject))
	}
	if ip != "" {
		fields = append(fields, F("ip", ip))
	}
	if reason != "" {
		fields = append(fields, F("reason", reason))
	}
	e.log(level, "auth_event", fields...)
}

// Authorization logs authorization events
// action: allow|deny
func (e *EventLogger) Authorization(action, subject, object, reason string) {
	level := InfoLevel
	if action == "deny" {
		level = WarnLevel // Denials are WARN
	}
	
	fields := []Field{
		F("event", "authorization"),
		F("action", action),
		F("object", object),
	}
	if subject != "" {
		fields = append(fields, F("subject", subject))
	}
	if reason != "" {
		fields = append(fields, F("reason", reason))
	}
	e.log(level, "authorization_event", fields...)
}

// Registration logs registration events
// action: attempt|approve|reject|replay|invalid_cert|invalid_sig|rate_limited
func (e *EventLogger) Registration(action, fingerprint, producerID, status, reason string) {
	level := InfoLevel
	switch action {
	case "replay", "invalid_cert", "invalid_sig", "rate_limited":
		level = WarnLevel // Security violations are WARN
	case "reject":
		level = WarnLevel // Rejections are WARN
	case "approve":
		level = InfoLevel // Approvals are INFO (security event)
	case "attempt":
		level = DebugLevel // Attempts can be DEBUG
	}
	
	fields := []Field{
		F("event", "registration"),
		F("action", action),
		F("fingerprint", fingerprint),
	}
	if producerID != "" {
		fields = append(fields, F("producer_id", producerID))
	}
	if status != "" {
		fields = append(fields, F("status", status))
	}
	if reason != "" {
		fields = append(fields, F("reason", reason))
	}
	e.log(level, "registration_event", fields...)
}

// Token logs token lifecycle events
// action: issue|exchange|revoke|verify
func (e *EventLogger) Token(action, producerID, subjectID, jti string, success bool, reason string) {
	level := InfoLevel
	if !success {
		level = WarnLevel // Failed token operations are WARN
	} else if action == "verify" {
		level = DebugLevel // Successful verifications are DEBUG
	}
	
	status := "success"
	if !success {
		status = "failed"
	}
	
	fields := []Field{
		F("event", "token"),
		F("action", action),
		F("status", status),
	}
	if producerID != "" {
		fields = append(fields, F("producer_id", producerID))
	}
	if subjectID != "" {
		fields = append(fields, F("subject_id", subjectID))
	}
	if jti != "" {
		fields = append(fields, F("jti", jti))
	}
	if reason != "" {
		fields = append(fields, F("reason", reason))
	}
	e.log(level, "token_event", fields...)
}

// Admin logs admin action events
// action: review|approve|deny|revoke|access
func (e *EventLogger) Admin(action, adminPrincipal, target, reason string, success bool) {
	level := InfoLevel
	if !success {
		level = ErrorLevel // Failed admin actions are ERROR
	}
	// Admin actions are always INFO or higher (security requirement)
	
	status := "success"
	if !success {
		status = "failed"
	}
	
	fields := []Field{
		F("event", "admin"),
		F("action", action),
		F("admin_principal", adminPrincipal),
		F("status", status),
	}
	if target != "" {
		fields = append(fields, F("target", target))
	}
	if reason != "" {
		fields = append(fields, F("reason", reason))
	}
	e.log(level, "admin_event", fields...)
}

// Infra logs infrastructure events
// action: connect|disconnect|error|retry|read|write|ack
// component: redis|postgres|http
// status: success|failed
func (e *EventLogger) Infra(action, component, status, details string) {
	level := DebugLevel
	if status == "failed" {
		level = ErrorLevel // Infrastructure failures are ERROR
	} else if action == "error" {
		level = ErrorLevel
	} else if action == "retry" {
		level = WarnLevel // Retries are WARN
	} else if status == "success" && (action == "connect" || action == "disconnect") {
		level = DebugLevel // Connection events are DEBUG when successful
	}
	
	fields := []Field{
		F("event", "infra"),
		F("action", action),
		F("component", component),
		F("status", status),
	}
	if details != "" {
		fields = append(fields, F("details", details))
	}
	e.log(level, "infra_event", fields...)
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

