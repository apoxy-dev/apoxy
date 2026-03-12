package apiserviceproxy

import (
	"log"
	"log/slog"
	"strings"
)

type reverseProxyErrorLogWriter struct{}

func (reverseProxyErrorLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	switch {
	case strings.Contains(msg, "httputil: ReverseProxy read error during body copy: unexpected EOF"),
		strings.Contains(msg, "httputil: ReverseProxy read error during body copy: context canceled"),
		strings.Contains(msg, "httputil: ReverseProxy read error during body copy: write: broken pipe"),
		strings.Contains(msg, "httputil: ReverseProxy read error during body copy: broken pipe"):
		slog.Debug("reverse proxy client disconnected", slog.String("message", msg))
	default:
		slog.Warn("reverse proxy internal error", slog.String("message", msg))
	}
	return len(p), nil
}

func newReverseProxyErrorLogger() *log.Logger {
	return log.New(reverseProxyErrorLogWriter{}, "", 0)
}
