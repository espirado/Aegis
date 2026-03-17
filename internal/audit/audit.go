// Package audit provides structured audit logging for AEGIS.
//
// Every request processed by AEGIS generates an immutable audit record
// containing classification results, verdicts, latency, and redaction details.
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/espirado/aegis/pkg/types"
)

// Logger writes audit records to configured outputs.
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	toStdout bool
	toFile   bool
	redact   bool
}

// Config for the audit logger.
type Config struct {
	Output              string `yaml:"output"` // "stdout", "file", "both"
	FilePath            string `yaml:"file_path"`
	RedactFlaggedContent bool  `yaml:"redact_flagged_content"`
}

// NewLogger creates an audit logger.
func NewLogger(cfg Config) (*Logger, error) {
	l := &Logger{
		redact: cfg.RedactFlaggedContent,
	}

	switch cfg.Output {
	case "stdout":
		l.toStdout = true
	case "file":
		l.toFile = true
	case "both":
		l.toStdout = true
		l.toFile = true
	default:
		l.toStdout = true
	}

	if l.toFile && cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			slog.Warn("audit: cannot open log file, falling back to stdout",
				"path", cfg.FilePath, "error", err)
			l.toStdout = true
			l.toFile = false
		} else {
			l.file = f
		}
	}

	return l, nil
}

// Log writes an audit record.
func (l *Logger) Log(record *types.AuditRecord) {
	data, err := json.Marshal(record)
	if err != nil {
		slog.Error("audit: marshal failed", "error", err, "request_id", record.RequestID)
		return
	}

	line := string(data) + "\n"

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.toStdout {
		fmt.Fprint(os.Stdout, line)
	}
	if l.toFile && l.file != nil {
		l.file.WriteString(line)
	}
}

// Close flushes and closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
