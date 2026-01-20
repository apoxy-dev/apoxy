// Package log provides logging routines based on slog package.
package log

import (
	"bytes"
	"io"
	"strings"
)

// SubprocessWriter wraps subprocess output lines as structured log entries.
// Each line from the subprocess is emitted as a separate log entry with the
// given source name and log level.
type SubprocessWriter struct {
	Source string   // e.g., "envoy", "coredns"
	Level  LogLevel // Log level for the output
	buf    bytes.Buffer
}

// NewSubprocessWriter creates a new SubprocessWriter.
func NewSubprocessWriter(source string, level LogLevel) *SubprocessWriter {
	return &SubprocessWriter{Source: source, Level: level}
}

// Write implements io.Writer. It buffers input and logs complete lines.
func (w *SubprocessWriter) Write(p []byte) (n int, err error) {
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err == io.EOF {
			// Put back incomplete line.
			w.buf.WriteString(line)
			break
		}
		if err != nil {
			return len(p), err
		}
		// Trim the newline and log.
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r") // Handle Windows-style line endings.
		if line != "" {
			logf(w.Level, "[%s] %s", w.Source, line)
		}
	}
	return len(p), nil
}
