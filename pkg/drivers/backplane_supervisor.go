package drivers

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	// DefaultLogsDir is the default directory for logs
	DefaultLogsDir = "/var/log/apoxy"
	// BackplaneStdoutLogFile is the name of the backplane stdout log file
	BackplaneStdoutLogFile = "backplane.stdout.log"
	// BackplaneStderrLogFile is the name of the backplane stderr log file
	BackplaneStderrLogFile = "backplane.stderr.log"
	// BackplaneProcessName is used to identify the backplane process
	BackplaneProcessName = "backplane"
)

// BackplaneSupervisorDriver implements the Driver interface for process supervision.
type BackplaneSupervisorDriver struct {
	// LogsDir is the directory where logs will be written
	LogsDir string
	cmd     *exec.Cmd
}

// NewBackplaneSupervisorDriver creates a new Supervisor driver with default configuration.
func NewBackplaneSupervisorDriver() *BackplaneSupervisorDriver {
	return &BackplaneSupervisorDriver{
		LogsDir: DefaultLogsDir,
	}
}

// WithLogsDir sets the logs directory for the supervisor driver.
func WithLogsDir(logsDir string) func(*BackplaneSupervisorDriver) {
	return func(d *BackplaneSupervisorDriver) {
		d.LogsDir = logsDir
	}
}

// Start implements the Driver interface.
func (d *BackplaneSupervisorDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	proxyName string,
	opts ...Option,
) (string, error) {
	setOpts := DefaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}

	if d.LogsDir != "" {
		if err := os.MkdirAll(d.LogsDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create logs directory %s: %w", d.LogsDir, err)
		}
	}

	if d.cmd != nil && d.cmd.Process != nil {
		if err := d.cmd.Process.Signal(os.Signal(nil)); err == nil {
			log.Infof("Backplane process already running with PID %d", d.cmd.Process.Pid)
			return fmt.Sprintf("%s-%s", BackplaneProcessName, proxyName), nil
		}
		d.cmd = nil
	}

	d.cmd = exec.CommandContext(ctx, BackplaneProcessName)

	d.cmd.Args = append(d.cmd.Args, []string{
		"--project_id=" + orgID.String(),
		// Use the same name for both proxy and replica - we only have one replica.
		"--proxy=" + proxyName,
		"--replica=" + proxyName,
		"--apiserver_addr=" + net.JoinHostPort("localhost", "8443"),
		"--controller_metrics_port=9981",
		"--health_probe_port=9988",
		"--metrics_port=9992",
		"--use_envoy_contrib=true",
		"--dev=true",
	}...)

	d.cmd.Args = append(d.cmd.Args, setOpts.Args...)

	if d.LogsDir != "" {
		stdoutPath := filepath.Join(d.LogsDir, BackplaneStdoutLogFile)
		stderrPath := filepath.Join(d.LogsDir, BackplaneStderrLogFile)

		stdoutFile, err := os.Create(stdoutPath)
		if err != nil {
			return "", fmt.Errorf("failed to create stdout log file %s: %w", stdoutPath, err)
		}

		stderrFile, err := os.Create(stderrPath)
		if err != nil {
			stdoutFile.Close()
			return "", fmt.Errorf("failed to create stderr log file %s: %w", stderrPath, err)
		}

		d.cmd.Stdout = stdoutFile
		d.cmd.Stderr = stderrFile

		log.Infof("Backplane logs will be written to %s and %s", stdoutPath, stderrPath)
	} else {
		d.cmd.Stdout = os.Stdout
		d.cmd.Stderr = os.Stderr
		log.Infof("Backplane logs will be written to stdout and stderr")
	}

	log.Infof("Starting backplane process with command: %v", d.cmd.Args)

	if err := d.cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start backplane process: %w", err)
	}

	log.Infof("Started backplane process with PID %d", d.cmd.Process.Pid)

	return fmt.Sprintf("%s-%s", BackplaneProcessName, proxyName), nil
}

// Stop implements the Driver interface.
func (d *BackplaneSupervisorDriver) Stop(orgID uuid.UUID, proxyName string) {
	if d.cmd == nil || d.cmd.Process == nil {
		log.Infof("No backplane process to stop")
		return
	}

	log.Infof("Stopping backplane process with PID %d", d.cmd.Process.Pid)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
		log.Errorf("Failed to send interrupt signal to backplane process: %v", err)
		if err := d.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to kill backplane process: %v", err)
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- d.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			log.Errorf("Backplane process exited with error: %v", err)
		} else {
			log.Infof("Backplane process exited successfully")
		}
	case <-ctx.Done():
		log.Errorf("Timeout waiting for backplane process to exit, forcing kill")
		if err := d.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to kill backplane process: %v", err)
		}
	}

	d.cmd = nil
}

// GetAddr implements the Driver interface.
func (d *BackplaneSupervisorDriver) GetAddr(ctx context.Context) (string, error) {
	return "localhost", nil
}
