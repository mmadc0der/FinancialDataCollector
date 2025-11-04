package logging

import (
	"net/http"
	"strings"
)

// EventLogger provides structured event logging with security-compliant schemas
type EventLogger struct {
	log func(level Level, msg string, fields ...Field)
}

var keyReplacer = strings.NewReplacer(" ", "_", "-", "_", "/", "_", ".", "_", ":", "_")

func normalizeToken(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeKey(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	sanitized := keyReplacer.Replace(lower)
	for strings.Contains(sanitized, "__") {
		sanitized = strings.ReplaceAll(sanitized, "__", "_")
	}
	sanitized = strings.Trim(sanitized, "_")
	if sanitized == "" {
		return lower
	}
	return sanitized
}

func httpStatusLabel(code int) string {
	if code == 0 {
		return ""
	}
	return normalizeToken(http.StatusText(code))
}

func appendReason(fields []Field, reason string, detailsSet bool) ([]Field, bool) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return fields, detailsSet
	}
	code := normalizeKey(trimmed)
	detail := ""
	if idx := strings.Index(trimmed, ":"); idx != -1 {
		head := strings.TrimSpace(trimmed[:idx])
		tail := strings.TrimSpace(trimmed[idx+1:])
		if head != "" {
			code = normalizeKey(head)
		}
		detail = tail
	}
	if code == "" {
		fields = append(fields, F("reason_code", trimmed))
		if detail != "" && !detailsSet {
			fields = append(fields, F("details", detail))
			detailsSet = true
		}
		return fields, detailsSet
	}
	fields = append(fields, F("reason_code", code))
	if detail != "" && !detailsSet {
		fields = append(fields, F("details", detail))
		detailsSet = true
	} else if detail == "" && !detailsSet && trimmed != code && strings.ContainsAny(trimmed, " \t") {
		fields = append(fields, F("details", trimmed))
		detailsSet = true
	}
	return fields, detailsSet
}

func registrationStage(action string) string {
	switch action {
	case "attempt", "message_received":
		return "request"
	case "message_invalid":
		return "request_validation"
	case "payload_invalid", "payload_validated":
		return "payload_validation"
	case "approve", "reject", "status_approved":
		return "approval"
	case "replay", "nonce_replay":
		return "nonce_guard"
	case "invalid_cert", "certificate_invalid":
		return "certificate_validation"
	case "invalid_sig", "signature_invalid":
		return "signature_verification"
	case "rate_limited":
		return "rate_limiting"
	case "status_check", "status_pending", "status_denied", "status_unknown":
		return "status"
	case "record_persisted":
		return "persistence"
	case "deregister_request", "deregistered":
		return "deregistration"
	case "success":
		return "registration"
	default:
		if action == "" {
			return "registration"
		}
		return action
	}
}

func registrationOutcome(action, status string) string {
	switch status {
	case "success", "approved", "ok":
		return "success"
	case "failed", "error", "invalid", "invalid_sig", "invalid_cert":
		return "failed"
	case "rate_limited", "denied":
		return "denied"
	case "pending", "waiting":
		return "pending"
	case "deregister", "deregistered":
		return "pending"
	case "attempt":
		return "attempt"
	}
	switch action {
	case "attempt":
		return "attempt"
	case "approve", "success":
		return "success"
	case "reject", "rate_limited":
		return "denied"
	case "replay", "invalid_cert", "invalid_sig", "error":
		return "failed"
	}
	if status != "" {
		return status
	}
	if action != "" {
		return action
	}
	return "unknown"
}

func registrationLevel(outcome string) Level {
	switch outcome {
	case "attempt", "pending":
		return InfoLevel
	case "success":
		return InfoLevel
	case "denied":
		return WarnLevel
	case "failed":
		return WarnLevel
	default:
		return InfoLevel
	}
}

func tokenStage(action string) string {
	if action == "" {
		return "token"
	}
	return "token_" + action
}

func adminStage(action string) string {
	if action == "" {
		return "admin"
	}
	return "admin_" + action
}

func infraStage(component, action string) string {
	switch {
	case component == "" && action == "":
		return "infra"
	case component == "":
		return action
	case action == "":
		return component
	default:
		return component + "_" + action
	}
}

func infraOutcome(status, action string) string {
	switch status {
	case "success", "ok", "ready":
		return "success"
	case "failed", "error", "timeout":
		return "failed"
	case "empty", "skipped", "noop":
		return "skipped"
	case "rate_limited", "denied":
		return "denied"
	case "retry":
		return "retry"
	case "":
		// fall through
	default:
		if status != "" {
			return status
		}
	}
	switch action {
	case "retry":
		return "retry"
	case "error", "failed":
		return "failed"
	case "start", "config", "init", "migrate":
		return "success"
	}
	return "unknown"
}

func isStartupAction(action string) bool {
	switch action {
	case "start", "config", "init", "migrate":
		return true
	default:
		return false
	}
}

func infraLevel(action, outcome string) Level {
	switch outcome {
	case "failed":
		return ErrorLevel
	case "retry":
		return WarnLevel
	case "skipped", "denied":
		return WarnLevel
	case "success":
		if isStartupAction(action) {
			return InfoLevel
		}
		return DebugLevel
	default:
		if action == "error" {
			return ErrorLevel
		}
		return InfoLevel
	}
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
	actionKey := normalizeKey(action)
	if actionKey == "" {
		actionKey = "unknown"
	}
	statusKey := normalizeKey(status)
	outcome := statusKey
	if outcome == "" {
		outcome = "success"
	}

	level := InfoLevel
	switch outcome {
	case "success":
		level = DebugLevel
	case "failed":
		if httpCode >= 500 {
			level = ErrorLevel
		} else {
			level = WarnLevel
		}
	default:
		if httpCode >= 500 {
			level = ErrorLevel
		} else if httpCode >= 400 {
			level = WarnLevel
		}
	}

	fields := []Field{
		F("event", "api"),
		F("component", "api"),
		F("stage", "request"),
		F("action", actionKey),
		F("outcome", outcome),
	}
	if from = strings.TrimSpace(from); from != "" {
		fields = append(fields, F("from", from))
	}
	if subject = strings.TrimSpace(subject); subject != "" {
		fields = append(fields, F("subject", subject))
	}
	if object = strings.TrimSpace(object); object != "" {
		fields = append(fields, F("object", object))
	}
	if statusKey != "" && statusKey != outcome {
		fields = append(fields, F("status", statusKey))
	}
	if httpCode != 0 {
		fields = append(fields, F("http_code", httpCode))
		if label := httpStatusLabel(httpCode); label != "" {
			fields = append(fields, F("http_status", label))
		}
	}
	fields, _ = appendReason(fields, reason, false)
	e.log(level, "api", fields...)
}

// Auth logs authentication events
// action: login|logout|verify|failure
func (e *EventLogger) Auth(action, subject, ip string, success bool, reason string) {
	actionKey := normalizeKey(action)
	if actionKey == "" {
		actionKey = "unknown"
	}

	outcome := "success"
	level := InfoLevel
	if success {
		level = DebugLevel
	} else {
		outcome = "failed"
		if actionKey == "failure" {
			level = ErrorLevel
		} else {
			level = WarnLevel
		}
	}

	fields := []Field{
		F("event", "auth"),
		F("component", "auth"),
		F("stage", "authentication"),
		F("action", actionKey),
		F("outcome", outcome),
	}
	if subject = strings.TrimSpace(subject); subject != "" {
		fields = append(fields, F("subject", subject))
	}
	if ip = strings.TrimSpace(ip); ip != "" {
		fields = append(fields, F("ip", ip))
	}
	fields, _ = appendReason(fields, reason, false)
	e.log(level, "auth", fields...)
}

// Authorization logs authorization events
// action: allow|deny
func (e *EventLogger) Authorization(action, subject, object, reason string) {
	actionKey := normalizeKey(action)
	if actionKey == "" {
		actionKey = "unknown"
	}

	outcome := "success"
	level := InfoLevel
	if actionKey == "deny" {
		outcome = "denied"
		level = WarnLevel
	}

	fields := []Field{
		F("event", "authorization"),
		F("component", "auth"),
		F("stage", "authorization"),
		F("action", actionKey),
		F("outcome", outcome),
	}
	if subject = strings.TrimSpace(subject); subject != "" {
		fields = append(fields, F("subject", subject))
	}
	if object = strings.TrimSpace(object); object != "" {
		fields = append(fields, F("object", object))
	}
	fields, _ = appendReason(fields, reason, false)
	e.log(level, "authorization", fields...)
}

// Registration logs registration events
// action: attempt|approve|reject|replay|invalid_cert|invalid_sig|rate_limited
func (e *EventLogger) Registration(action, fingerprint, producerID, status, reason string) {
	actionKey := normalizeKey(action)
	statusKey := normalizeKey(status)

	stage := registrationStage(actionKey)
	outcome := registrationOutcome(actionKey, statusKey)
	level := registrationLevel(outcome)

	actionField := actionKey
	if actionField == "" {
		actionField = "unknown"
	}

	fields := []Field{
		F("event", "registration"),
		F("component", "registration"),
		F("stage", stage),
		F("action", actionField),
		F("outcome", outcome),
	}
	if fingerprint = strings.TrimSpace(fingerprint); fingerprint != "" {
		fields = append(fields, F("fingerprint", fingerprint))
	}
	if producerID = strings.TrimSpace(producerID); producerID != "" {
		fields = append(fields, F("producer_id", producerID))
	}
	if statusKey != "" && statusKey != outcome {
		fields = append(fields, F("status", statusKey))
	}
	if reason != "" {
		fields, _ = appendReason(fields, reason, false)
	} else if actionKey != "" && actionKey != outcome {
		fields = append(fields, F("reason_code", actionKey))
	}
	e.log(level, "registration", fields...)
}

// Token logs token lifecycle events
// action: issue|exchange|revoke|verify
func (e *EventLogger) Token(action, producerID, subjectID, jti string, success bool, reason string) {
	actionKey := normalizeKey(action)
	stage := tokenStage(actionKey)

	outcome := "success"
	level := InfoLevel
	if actionKey == "verify" && success {
		level = DebugLevel
	} else if !success {
		outcome = "failed"
		level = WarnLevel
	}

	actionField := actionKey
	if actionField == "" {
		actionField = "unknown"
	}

	fields := []Field{
		F("event", "token"),
		F("component", "auth"),
		F("stage", stage),
		F("action", actionField),
		F("outcome", outcome),
	}
	if producerID = strings.TrimSpace(producerID); producerID != "" {
		fields = append(fields, F("producer_id", producerID))
	}
	if subjectID = strings.TrimSpace(subjectID); subjectID != "" {
		fields = append(fields, F("subject_id", subjectID))
	}
	if jti = strings.TrimSpace(jti); jti != "" {
		fields = append(fields, F("jti", jti))
	}
	if !success {
		fields = append(fields, F("status", "failed"))
	}
	fields, _ = appendReason(fields, reason, false)
	e.log(level, "token", fields...)
}

// Admin logs admin action events
// action: review|approve|deny|revoke|access
func (e *EventLogger) Admin(action, adminPrincipal, target, reason string, success bool) {
	actionKey := normalizeKey(action)
	stage := adminStage(actionKey)

	outcome := "success"
	level := InfoLevel
	if !success {
		outcome = "failed"
		level = ErrorLevel
	}

	actionField := actionKey
	if actionField == "" {
		actionField = "unknown"
	}

	fields := []Field{
		F("event", "admin"),
		F("component", "admin"),
		F("stage", stage),
		F("action", actionField),
		F("outcome", outcome),
	}
	if adminPrincipal = strings.TrimSpace(adminPrincipal); adminPrincipal != "" {
		fields = append(fields, F("admin_principal", adminPrincipal))
	}
	if target = strings.TrimSpace(target); target != "" {
		fields = append(fields, F("target", target))
	}
	fields, _ = appendReason(fields, reason, false)
	e.log(level, "admin", fields...)
}

// Infra logs infrastructure events
// action: connect|disconnect|error|retry|read|write|ack|start|config|init|migrate
// component: redis|postgres|http
// status: success|failed|empty
func (e *EventLogger) Infra(action, component, status, details string) {
	actionKey := normalizeKey(action)
	componentKey := normalizeKey(component)
	statusKey := normalizeKey(status)

	outcome := infraOutcome(statusKey, actionKey)
	stage := infraStage(componentKey, actionKey)
	level := infraLevel(actionKey, outcome)

	actionField := actionKey
	if actionField == "" {
		actionField = "unknown"
	}
	componentField := componentKey
	if componentField == "" {
		componentField = "infra"
	}

	fields := []Field{
		F("event", "infra"),
		F("component", componentField),
		F("stage", stage),
		F("action", actionField),
		F("outcome", outcome),
	}
	if statusKey != "" && statusKey != outcome {
		fields = append(fields, F("status", statusKey))
	}
	if details = strings.TrimSpace(details); details != "" {
		fields = append(fields, F("details", details))
	}
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
