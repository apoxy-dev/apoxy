// Package otel provides functionality for managing OpenTelemetry collector processes.
package otel

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	// DefaultCollectorBinary is the default path to the otel-collector binary
	DefaultCollectorBinary = "/bin/otel-collector"

	// DefaultLogsDir is the default directory for logs
	DefaultLogsDir = "/var/log/apoxy"

	// CollectorStdoutLogFile is the name of the collector stdout log file
	CollectorStdoutLogFile = "otel-collector.stdout.log"

	// CollectorStderrLogFile is the name of the collector stderr log file
	CollectorStderrLogFile = "otel-collector.stderr.log"

	// DefaultConfigPath is the default path to the otel-collector config file
	DefaultConfigPath = "/etc/otelcol/config.yaml"

	// Default collector port
	DefaultCollectorPort = 4317
)

// TemplateVars represents the variables used in the OpenTelemetry collector config template
type TemplateVars struct {
	OTLPPort                    int
	ClickHouseAddr              string
	ClickHouseDatabase          string
	EnableClickHouse            bool
	OTLPTracesEndpoint          string
	OTLPTracesProtocol          string
	OTLPTracesInsecure          bool
	OTLPTracesCertificate       string
	OTLPTracesClientKey         string
	OTLPTracesClientCertificate string
	OTLPTracesHeaders           map[string]string
}

//go:embed config_template.yaml
var configTemplate embed.FS

// RenderConfigTemplate renders the OpenTelemetry collector config template with the provided variables
func RenderConfigTemplate(vars TemplateVars) (string, error) {
	tmplContent, err := configTemplate.ReadFile("config_template.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to read config template: %w", err)
	}

	tmpl, err := template.New("otel-config").Parse(string(tmplContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse config template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return "", fmt.Errorf("failed to render config template: %w", err)
	}

	return buf.String(), nil
}

// Option configures a Collector.
type Option func(*Collector)

// WithCollectorBinary sets the path to the otel-collector binary.
func WithCollectorBinary(path string) Option {
	return func(c *Collector) {
		c.CollectorBinary = path
	}
}

// WithLogsDir sets the directory where logs will be written.
func WithLogsDir(path string) Option {
	return func(c *Collector) {
		c.LogsDir = path
	}
}

// WithArgs sets additional arguments to pass to the otel-collector.
func WithArgs(args ...string) Option {
	return func(c *Collector) {
		c.Args = append(c.Args, args...)
	}
}

// WithConfig sets the configuration file path for the otel-collector.
func WithConfig(configPath string) Option {
	return func(c *Collector) {
		c.ConfigPath = configPath
	}
}

// Collector manages the OpenTelemetry collector process.
type Collector struct {
	// CollectorBinary is the path to the otel-collector binary
	CollectorBinary string
	// LogsDir is the directory where logs will be written
	LogsDir string
	// ConfigPath is the path to the otel-collector config file
	ConfigPath string
	// Args are additional arguments to pass to the otel-collector
	Args []string
	// ClickHouseOpts are the options for the ClickHouse exporter
	ClickHouseOpts *clickhouse.Options

	cmd         *exec.Cmd
	stopCh      chan struct{}
	mu          sync.RWMutex
	status      CollectorStatus
	wroteConfig bool
}

// CollectorStatus represents the status of the otel-collector process.
type CollectorStatus struct {
	StartedAt time.Time
	Running   bool
	ProcState *os.ProcessState
}

// Status returns the current status of the otel-collector process.
func (c *Collector) Status() CollectorStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// setOptions applies the provided options to the Collector.
func (c *Collector) setOptions(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}

	// Set defaults if not provided
	if c.CollectorBinary == "" {
		c.CollectorBinary = DefaultCollectorBinary
	}

	if c.LogsDir == "" {
		c.LogsDir = DefaultLogsDir
	}
}

// Start starts the otel-collector process.
func (c *Collector) Start(ctx context.Context, opts ...Option) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply options
	c.setOptions(opts...)

	// Check if already running
	if c.cmd != nil && c.cmd.Process != nil {
		// Check if process is still running
		if err := c.cmd.Process.Signal(os.Signal(nil)); err == nil {
			log.Infof("OpenTelemetry collector already running with PID %d", c.cmd.Process.Pid)
			return nil
		}
		// Process is not running, clean up
		c.cmd = nil
	}

	// Ensure logs directory exists
	if c.LogsDir != "" {
		if err := os.MkdirAll(c.LogsDir, 0755); err != nil {
			return fmt.Errorf("failed to create logs directory %s: %w", c.LogsDir, err)
		}
	}

	// Check if default config file exists, if not, create it
	if c.ConfigPath == "" {
		// Check if default config file exists
		if _, err := os.Stat(DefaultConfigPath); os.IsNotExist(err) {
			// Create directory if it doesn't exist
			if err := os.MkdirAll(filepath.Dir(DefaultConfigPath), 0755); err != nil {
				return fmt.Errorf("failed to create config directory %s: %w", filepath.Dir(DefaultConfigPath), err)
			}

			chAddrs := []string{}
			chAddr := ""
			clickHouseDatabase := "default"
			enableClickHouse := false
			if c.ClickHouseOpts != nil {
				enableClickHouse = true
				for _, addr := range c.ClickHouseOpts.Addr {
					chAddrs = append(chAddrs, fmt.Sprintf("clickhouse://%s", addr))
				}
				chAddr = strings.Join(chAddrs, ",")
				if c.ClickHouseOpts.Auth.Database != "" {
					clickHouseDatabase = c.ClickHouseOpts.Auth.Database
				}
			}

			// The following implements the OpenTelemetry specification available at:
			// https://github.com/open-telemetry/opentelemetry-specification/blob/e711f74df1b6c967a9c923fe34e64a78ebd15af1/specification/protocol/exporter.md
			otlpTracesEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
			if otlpTracesEndpoint == "" {
				otlpTracesEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
			}
			otlpTracesProtocol := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
			if otlpTracesProtocol == "" {
				otlpTracesProtocol = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
				if otlpTracesProtocol == "" {
					otlpTracesProtocol = "grpc"
				}
			}
			if otlpTracesProtocol != "grpc" && otlpTracesProtocol != "http/protobuf" && otlpTracesProtocol != "http/json" {
				return fmt.Errorf("unsupported protocol: %s", otlpTracesProtocol)
			}
			otlpTracesInsecure := false
			if insecureStr := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_INSECURE"); insecureStr != "" {
				otlpTracesInsecure = insecureStr == "true"
			} else if insecureStr := os.Getenv("OTEL_EXPORTER_OTLP_INSECURE"); insecureStr != "" {
				otlpTracesInsecure = insecureStr == "true"
			}
			otlpTracesCertificate := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE")
			if otlpTracesCertificate == "" {
				otlpTracesCertificate = os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE")
			}
			otlpTracesClientKey := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY")
			if otlpTracesClientKey == "" {
				otlpTracesClientKey = os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_KEY")
			}
			otlpTracesClientCertificate := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE")
			if otlpTracesClientCertificate == "" {
				otlpTracesClientCertificate = os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE")
			}
			otlpTracesHeadersMap := make(map[string]string)
			otlpTracesHeaders := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS")
			for _, s := range strings.Split(otlpTracesHeaders, ",") {
				if strings.TrimSpace(s) == "" {
					continue
				}
				kv := strings.Split(strings.TrimSpace(s), "=")
				if len(kv) != 2 {
					return fmt.Errorf("invalid header format: %s", s)
				}
				otlpTracesHeadersMap[kv[0]] = kv[1]
			}

			vars := TemplateVars{
				OTLPPort:                    DefaultCollectorPort,
				EnableClickHouse:            enableClickHouse,
				ClickHouseAddr:              chAddr,
				ClickHouseDatabase:          clickHouseDatabase,
				OTLPTracesEndpoint:          otlpTracesEndpoint,
				OTLPTracesProtocol:          otlpTracesProtocol,
				OTLPTracesInsecure:          otlpTracesInsecure,
				OTLPTracesCertificate:       otlpTracesCertificate,
				OTLPTracesClientKey:         otlpTracesClientKey,
				OTLPTracesClientCertificate: otlpTracesClientCertificate,
				OTLPTracesHeaders:           otlpTracesHeadersMap,
			}
			configContent, err := RenderConfigTemplate(vars)
			if err != nil {
				return fmt.Errorf("failed to render config template: %w", err)
			}

			if err := os.WriteFile(DefaultConfigPath, []byte(configContent), 0644); err != nil {
				return fmt.Errorf("failed to create default config file %s: %w", DefaultConfigPath, err)
			}
			c.wroteConfig = true
			log.Infof("Created default OpenTelemetry collector config at %s", DefaultConfigPath)
		} else if err != nil {
			return fmt.Errorf("failed to check if config file exists %s: %w", DefaultConfigPath, err)
		} else {
			log.Infof("Using existing OpenTelemetry collector config at %s", DefaultConfigPath)
		}

		// Use default config file
		c.ConfigPath = DefaultConfigPath
	}

	// Prepare command
	c.cmd = exec.CommandContext(ctx, c.CollectorBinary)

	// Add standard arguments
	args := []string{}

	// Add config file if specified
	if c.ConfigPath != "" {
		args = append(args, "--config", c.ConfigPath)
	}

	// Add user-provided arguments
	args = append(args, c.Args...)
	c.cmd.Args = append(c.cmd.Args, args...)

	// Set up output redirection
	if c.LogsDir != "" {
		// Create or truncate log files
		stdoutPath := filepath.Join(c.LogsDir, CollectorStdoutLogFile)
		stderrPath := filepath.Join(c.LogsDir, CollectorStderrLogFile)

		stdoutFile, err := os.Create(stdoutPath)
		if err != nil {
			return fmt.Errorf("failed to create stdout log file %s: %w", stdoutPath, err)
		}

		stderrFile, err := os.Create(stderrPath)
		if err != nil {
			stdoutFile.Close()
			return fmt.Errorf("failed to create stderr log file %s: %w", stderrPath, err)
		}

		c.cmd.Stdout = stdoutFile
		c.cmd.Stderr = stderrFile

		log.Infof("OpenTelemetry collector logs will be written to %s and %s", stdoutPath, stderrPath)
	} else {
		// Use os.Stdout and os.Stderr directly
		c.cmd.Stdout = os.Stdout
		c.cmd.Stderr = os.Stderr
		log.Infof("OpenTelemetry collector logs will be written to stdout and stderr")
	}

	log.Infof("Starting OpenTelemetry collector process with command: %v", c.cmd.Args)

	// Start the process
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start OpenTelemetry collector process: %w", err)
	}

	log.Infof("Started OpenTelemetry collector process with PID %d", c.cmd.Process.Pid)

	// Update status
	c.status = CollectorStatus{
		StartedAt: time.Now(),
		Running:   true,
	}

	// Create stop channel
	c.stopCh = make(chan struct{})

	// Monitor process in background
	go func() {
		err := c.cmd.Wait()

		c.mu.Lock()
		defer c.mu.Unlock()

		c.status.Running = false
		c.status.ProcState = c.cmd.ProcessState

		if err != nil {
			log.Errorf("OpenTelemetry collector process exited with error: %v", err)
		} else {
			log.Infof("OpenTelemetry collector process exited successfully")
		}

		if c.wroteConfig {
			// Clean up the config file if we wrote it.
			if err := os.Remove(c.ConfigPath); err != nil {
				log.Errorf("Failed to remove config file %s: %v", c.ConfigPath, err)
			}
		}

		// Signal that the process has stopped if that hasn't already been signalled.
		select {
		case <-c.stopCh:
		default:
			close(c.stopCh)
		}
	}()

	return nil
}

// Stop stops the otel-collector process.
func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()

	// Check if already stopped
	if c.cmd == nil || c.cmd.Process == nil {
		c.mu.Unlock()
		log.Infof("No OpenTelemetry collector process to stop")
		return nil
	}

	stopCh := c.stopCh
	pid := c.cmd.Process.Pid
	c.mu.Unlock()

	log.Infof("Stopping OpenTelemetry collector process with PID %d", pid)

	// Try to terminate gracefully first
	if err := c.cmd.Process.Signal(os.Interrupt); err != nil {
		log.Errorf("Failed to send interrupt signal to OpenTelemetry collector process: %v", err)
		// Try to kill forcefully
		if err := c.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill OpenTelemetry collector process: %v", err)
		}
	}

	// Wait for process to exit or timeout
	select {
	case <-stopCh:
		log.Infof("OpenTelemetry collector process stopped")
	case <-ctx.Done():
		log.Errorf("Timeout waiting for OpenTelemetry collector process to exit, forcing kill")
		c.mu.Lock()
		if c.cmd != nil && c.cmd.Process != nil {
			if err := c.cmd.Process.Kill(); err != nil {
				c.mu.Unlock()
				return fmt.Errorf("failed to kill OpenTelemetry collector process: %v", err)
			}
		}
		c.mu.Unlock()
	}

	return nil
}
