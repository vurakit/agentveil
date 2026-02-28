package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Setup initializes structured JSON logging at the given level.
// Returns the logger instance.
func Setup(level string, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}

	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: lvl,
	})

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}

// AuditEvent represents a structured audit trail entry
type AuditEvent struct {
	Action     string   `json:"action"`      // "anonymize", "rehydrate", "audit", "auth"
	SessionID  string   `json:"session_id"`
	Role       string   `json:"role"`
	PIICount   int      `json:"pii_count"`
	Categories []string `json:"categories"`  // PII categories found
	RiskScore  float64  `json:"risk_score"`  // for audit events
	KeyID      string   `json:"key_id"`      // authenticated API key
	Path       string   `json:"path"`
	Method     string   `json:"method"`
	StatusCode int      `json:"status_code"`
}

// Log writes an audit event to the structured logger
func (e AuditEvent) Log(logger *slog.Logger) {
	attrs := []slog.Attr{
		slog.String("action", e.Action),
		slog.String("session_id", e.SessionID),
		slog.String("method", e.Method),
		slog.String("path", e.Path),
		slog.Int("status_code", e.StatusCode),
	}

	if e.Role != "" {
		attrs = append(attrs, slog.String("role", e.Role))
	}
	if e.PIICount > 0 {
		attrs = append(attrs, slog.Int("pii_count", e.PIICount))
	}
	if len(e.Categories) > 0 {
		attrs = append(attrs, slog.String("categories", strings.Join(e.Categories, ",")))
	}
	if e.RiskScore > 0 {
		attrs = append(attrs, slog.Float64("risk_score", e.RiskScore))
	}
	if e.KeyID != "" {
		attrs = append(attrs, slog.String("key_id", e.KeyID))
	}

	args := make([]any, len(attrs))
	for i, a := range attrs {
		args[i] = a
	}
	logger.Info("audit", args...)
}
