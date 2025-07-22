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

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

const (
	// DefaultTunnelProxyLogsDir is the default directory for logs
	DefaultTunnelProxyLogsDir = "/var/log/apoxy"
	// TunnelProxyStdoutLogFile is the name of the tunnelproxy stdout log file
	TunnelProxyStdoutLogFile = "tunnelproxy.stdout.log"
	// TunnelProxyStderrLogFile is the name of the tunnelproxy stderr log file
	TunnelProxyStderrLogFile = "tunnelproxy.stderr.log"
	// TunnelProxyProcessName is used to identify the tunnelproxy process
	TunnelProxyProcessName = "tunnelproxy"
)

// TunnelProxySupervisorDriver implements the Driver interface for process supervision.
type TunnelProxySupervisorDriver struct {
	// LogsDir is the directory where logs will be written
	LogsDir string
	cmd     *exec.Cmd
}

// NewTunnelProxySupervisorDriver creates a new Supervisor driver with default configuration.
func NewTunnelProxySupervisorDriver() *TunnelProxySupervisorDriver {
	return &TunnelProxySupervisorDriver{
		LogsDir: DefaultTunnelProxyLogsDir,
	}
}

// WithTunnelProxyLogsDir sets the logs directory for the supervisor driver.
func WithTunnelProxyLogsDir(logsDir string) func(*TunnelProxySupervisorDriver) {
	return func(d *TunnelProxySupervisorDriver) {
		d.LogsDir = logsDir
	}
}

// Start implements the Driver interface.
func (d *TunnelProxySupervisorDriver) Start(
	ctx context.Context,
	projectID uuid.UUID,
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
			log.Infof("TunnelProxy process already running with PID %d", d.cmd.Process.Pid)
			return fmt.Sprintf("%s-%s", TunnelProxyProcessName, proxyName), nil
		}
		d.cmd = nil
	}

	certsDir := "/etc/apoxy/certs"

	log.Infof("Generating self-signed certificates at %s and %s",
		filepath.Join(certsDir, "tunnelproxy.crt"),
		filepath.Join(certsDir, "tunnelproxy.key"))

	_, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	if err != nil {
		return "", fmt.Errorf("failed to generate self-signed certificates: %w", err)
	}

	if err := cryptoutils.SaveCertificatePEM(serverCert, certsDir, "tunnelproxy", false); err != nil {
		return "", fmt.Errorf("failed to save CA certificate: %w", err)
	}

	d.cmd = exec.CommandContext(ctx, TunnelProxyProcessName)

	d.cmd.Args = append(d.cmd.Args, []string{
		"--dev=true",
		"--apiserver_addr=" + net.JoinHostPort("localhost", "8443"),
		"--network_id=" + projectID.String()[len(projectID.String())-8:],
		"--jwks_urls=http://localhost:8444" + token.JWKSURI,
		"--health_probe_port=9998",
		"--metrics_port=9993",
		"--cksum_recalc=true",
	}...)

	d.cmd.Args = append(d.cmd.Args, setOpts.Args...)

	if d.LogsDir != "" {
		stdoutPath := filepath.Join(d.LogsDir, TunnelProxyStdoutLogFile)
		stderrPath := filepath.Join(d.LogsDir, TunnelProxyStderrLogFile)

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

		log.Infof("TunnelProxy logs will be written to %s and %s", stdoutPath, stderrPath)
	} else {
		d.cmd.Stdout = os.Stdout
		d.cmd.Stderr = os.Stderr
		log.Infof("TunnelProxy logs will be written to stdout and stderr")
	}

	log.Infof("Starting tunnelproxy process with command: %v", d.cmd.Args)

	if err := d.cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start tunnelproxy process: %w", err)
	}

	log.Infof("Started tunnelproxy process with PID %d", d.cmd.Process.Pid)

	return fmt.Sprintf("%s-%s", TunnelProxyProcessName, proxyName), nil
}

// Stop implements the Driver interface.
func (d *TunnelProxySupervisorDriver) Stop(orgID uuid.UUID, proxyName string) {
	if d.cmd == nil || d.cmd.Process == nil {
		log.Infof("No tunnelproxy process to stop")
		return
	}

	log.Infof("Stopping tunnelproxy process with PID %d", d.cmd.Process.Pid)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
		log.Errorf("Failed to send interrupt signal to tunnelproxy process: %v", err)
		if err := d.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to kill tunnelproxy process: %v", err)
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- d.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			log.Errorf("TunnelProxy process exited with error: %v", err)
		} else {
			log.Infof("TunnelProxy process exited successfully")
		}
	case <-ctx.Done():
		log.Errorf("Timeout waiting for tunnelproxy process to exit, forcing kill")
		if err := d.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to kill tunnelproxy process: %v", err)
		}
	}

	d.cmd = nil
}

// GetAddr implements the Driver interface.
func (d *TunnelProxySupervisorDriver) GetAddr(ctx context.Context) (string, error) {
	return "localhost", nil
}
