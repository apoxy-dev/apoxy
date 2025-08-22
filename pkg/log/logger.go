// Package log provides logging routines based on slog package.
package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc/grpclog"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

type logWriterWrapper struct {
	l     *slog.Logger
	level LogLevel
}

func (w *logWriterWrapper) Write(p []byte) (n int, err error) {
	w.l.Log(context.Background(), w.level, string(p))
	return len(p), nil
}

// NewDefaultLogWriter returns a io.Writer that logs to the given logger at the given level.
func NewDefaultLogWriter(level LogLevel) io.Writer {
	return &logWriterWrapper{l: DefaultLogger, level: level}
}

func setDefaultLogger(level LogLevel, json bool, w io.Writer) {
	replace := func(groups []string, a slog.Attr) slog.Attr {
		// Remove the directory from the source's filename.
		if a.Key == slog.SourceKey {
			if s, ok := a.Value.Any().(*slog.Source); ok {
				s.File = filepath.Base(s.File)
			}
		}
		return a
	}
	opts := &slog.HandlerOptions{
		AddSource:   true,
		Level:       level,
		ReplaceAttr: replace,
	}
	logger := slog.New(slog.NewTextHandler(w, opts))
	if json {
		logger = slog.New(slog.NewJSONHandler(w, opts))
	}
	slog.SetDefault(logger)
}

var (
	initTime                 time.Time
	createLogFileIfNotExists func() (io.Writer, error)
)

func init() {
	initTime = time.Now()
	lpath := filepath.Join(os.TempDir(), fmt.Sprintf("apoxy-cli-%s.log", initTime.Format("2006-01-02T15:04:05.000Z")))
	createLogFileIfNotExists = sync.OnceValues(func() (io.Writer, error) {
		return os.OpenFile(lpath, os.O_CREATE|os.O_WRONLY, 0644)
	})
}

type LogLevel = slog.Level

const (
	DebugLevel = slog.LevelDebug
	InfoLevel  = slog.LevelInfo
	WarnLevel  = slog.LevelWarn
	ErrorLevel = slog.LevelError
)

// DefaultLogger is the default logger.
var DefaultLogger = slog.Default()

// Option is a logger option.
type Option func(*options)

type options struct {
	level           LogLevel
	json            bool
	alsoLogToStderr bool
}

func defaultOptions() *options {
	return &options{
		level:           InfoLevel,
		json:            false,
		alsoLogToStderr: false,
	}
}

// WithDevMode sets the logger to development mode.
// In development mode, the logger logs in human-readable format, the level is set to DebugLevel,
// and logs are also written to stderr.
func WithDevMode() Option {
	return func(o *options) {
		o.json = false
		o.level = DebugLevel
		o.alsoLogToStderr = true
	}
}

// WithAlsoLogToStderr also logs to stderr.
func WithAlsoLogToStderr() Option {
	return func(o *options) {
		o.alsoLogToStderr = true
	}
}

// WithLevel sets the log level.
// The default log level is InfoLevel.
func WithLevel(level LogLevel) Option {
	return func(o *options) {
		o.level = level
	}
}

// WithLevelString sets the log level.
func WithLevelString(level string) Option {
	return func(o *options) {
		switch strings.ToLower(level) {
		case "debug":
			o.level = DebugLevel
		case "info":
			o.level = InfoLevel
		case "warn":
			o.level = WarnLevel
		case "error":
			o.level = ErrorLevel
		default:
			o.level = InfoLevel
		}
	}
}

// Init initializes the logger.
func Init(opts ...Option) error {
	sOpts := defaultOptions()
	for _, opt := range opts {
		opt(sOpts)
	}

	logW, err := createLogFileIfNotExists()
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	if sOpts.alsoLogToStderr {
		logW = io.MultiWriter(os.Stderr, logW)
	}

	setDefaultLogger(sOpts.level, sOpts.json, logW)

	klog.SetSlogLogger(DefaultLogger)
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(
		NewDefaultLogWriter(InfoLevel),
		NewDefaultLogWriter(WarnLevel),
		NewDefaultLogWriter(ErrorLevel),
	))

	ctrl.SetLogger(logr.FromSlogHandler(DefaultLogger.Handler()))

	return nil
}

func Disable() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func logf(level slog.Level, format string, args ...any) {
	ctx := context.Background()
	logger := slog.Default()
	if !logger.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // skip [Callers, logf, Infof]
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(ctx, r)
}

// Debugf logs a debug message.
func Debugf(format string, args ...any) {
	level := slog.LevelDebug
	logf(level, format, args...)
}

// Infof logs an info message.
func Infof(format string, args ...any) {
	level := slog.LevelInfo
	logf(level, format, args...)
}

// Warnf logs a warning message.
func Warnf(format string, args ...any) {
	level := slog.LevelWarn
	logf(level, format, args...)
}

// Errorf logs an error message.
func Errorf(format string, args ...any) {
	level := slog.LevelError
	logf(level, format, args...)
}

// Fatalf logs a fatal message.
func Fatalf(format string, args ...any) {
	level := slog.LevelError
	logf(level, format, args...)
	os.Exit(1)
}

// New returns a new logr.Logger.
// deprecated: Remove usage and this method.
func New(enabled bool) logr.Logger {
	return logr.FromSlogHandler(slog.Default().Handler())
}

// FromContext returns an slog.Logger from the context.
func FromContext(ctx context.Context) *slog.Logger {
	return logr.FromContextAsSlogLogger(ctx)
}

// IntoContext returns a new context with the provided logger.
func IntoContext(ctx context.Context, logger *slog.Logger) context.Context {
	return logr.NewContextWithSlogLogger(ctx, logger)
}
