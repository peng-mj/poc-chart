// Package logging configures the structured logger for the application.
package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Setup configures the default slog logger.
//
// The logger writes to stderr using a text handler at the given level.
// This keeps stdout clean for user-facing CLI output (printed via fmt).
//
// Output format: [LEVEL]YYYY-MM-DD HH:MM:SS.mmm message
func Setup(level slog.Level) {
	handler := &compactHandler{
		handler: slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}),
	}
	slog.SetDefault(slog.New(handler))
}

// compactHandler is a custom slog handler that outputs logs in a compact format.
// Format: [LEVEL]YYYY-MM-DD HH:MM:SS.mmm message key=value...
type compactHandler struct {
	handler slog.Handler
}

func (h *compactHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *compactHandler) Handle(ctx context.Context, r slog.Record) error {
	// Build output: [LEVEL]timestamp message key=value...
	var sb strings.Builder

	// Level in brackets
	levelStr := levelToString(r.Level)
	sb.WriteString("[")
	sb.WriteString(levelStr)
	sb.WriteString("]")

	// Timestamp with milliseconds
	timestamp := r.Time.Format("2006-01-02 15:04:05.000")
	sb.WriteString(timestamp)
	sb.WriteString(" ")

	// Message
	sb.WriteString(r.Message)

	// Attributes as key=value (excluding time, level, msg which are already shown)
	r.Attrs(func(a slog.Attr) bool {
		key := a.Key
		// Skip standard keys that are already formatted
		if key == slog.TimeKey || key == slog.LevelKey || key == slog.MessageKey {
			return true
		}
		sb.WriteString(" ")
		sb.WriteString(key)
		sb.WriteString("=")
		sb.WriteString(a.Value.String())
		return true
	})

	sb.WriteString("\n")
	_, err := os.Stderr.Write([]byte(sb.String()))
	return err
}

func (h *compactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &compactHandler{
		handler: h.handler.WithAttrs(attrs),
	}
}

func (h *compactHandler) WithGroup(name string) slog.Handler {
	return &compactHandler{
		handler: h.handler.WithGroup(name),
	}
}

// levelToString converts slog.Level to a short string.
func levelToString(level slog.Level) string {
	switch level {
	case slog.LevelDebug:
		return "DEBUG"
	case slog.LevelInfo:
		return "INFO"
	case slog.LevelWarn:
		return "WARN"
	case slog.LevelError:
		return "ERROR"
	default:
		return fmt.Sprintf("%d", level)
	}
}

// Fatal logs an error message at the Error level and exits with status 1.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
