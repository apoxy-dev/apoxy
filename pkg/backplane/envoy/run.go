package envoy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/process"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/backplane/logs"
	"github.com/apoxy-dev/apoxy/pkg/backplane/otel"
	_ "github.com/apoxy-dev/apoxy/pkg/gateway/xds/extensions"
	xdstypes "github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/log"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

const (
	githubURL = "github.com/envoyproxy/envoy/releases/download"

	accessLogsPath = "/var/log/accesslogs"
	tapsPath       = "/var/log/taps"

	defaultDrainTimeoutSeconds = 30
)

var (
	goArchToPlatform = map[string]string{
		"amd64": "x86_64",
		"arm64": "aarch_64",
	}
)

// Option configures a Runtime.
type Option func(*Runtime)

// WithBootstrapConfigYAML sets the Envoy bootstrap config YAML.
func WithBootstrapConfigYAML(yaml string) Option {
	return func(r *Runtime) {
		r.BootstrapConfigYAML = yaml
	}
}

// WithCluster sets the Envoy cluster name.
// If this is not set, a random cluster name is used.
// The cluster name is used in the Envoy bootstrap config.
func WithCluster(cluster string) Option {
	return func(r *Runtime) {
		r.Cluster = cluster
	}
}

// WithArgs sets additional arguments to pass to Envoy.
// The arguments are appended to the default arguments.
func WithArgs(args ...string) Option {
	return func(r *Runtime) {
		r.Args = append(r.Args, args...)
	}
}

// WithRelease sets the Envoy release to use.
// If this is not set, the latest release is used.
func WithRelease(release ReleaseDownloader) Option {
	return func(r *Runtime) {
		r.Release = release
	}
}

// WithLogsCollector sets the logs collector.
func WithLogsCollector(c logs.LogsCollector) Option {
	return func(r *Runtime) {
		r.logs = c
	}
}

// WithGoPluginDir sets the directory to load Go plugins from.
func WithGoPluginDir(dir string) Option {
	return func(r *Runtime) {
		r.goPluginDir = dir
	}
}

// WithAdminHost sets the host for the Envoy admin interface.
func WithAdminHost(host string) Option {
	return func(r *Runtime) {
		r.adminHost = host
	}
}

// WithNodeMetadata sets the metadata for the Envoy node in XDS discovery requests.
// The metadata will be included in the node configuration and sent to the control plane.
func WithNodeMetadata(metadata *xdstypes.NodeMetadata) Option {
	return func(r *Runtime) {
		r.nodeMetadata = metadata
	}
}

// If this is not set, the default timeout is used (30 seconds).
func WithDrainTimeout(timeout *time.Duration) Option {
	return func(r *Runtime) {
		r.drainTimeout = timeout
	}
}

// If this is not set, the default timeout is used (30 seconds).
func WithMinDrainTime(timeout *time.Duration) Option {
	return func(r *Runtime) {
		r.minDrainTime = timeout
	}
}

// WithOtelCollector sets the OpenTelemetry collector.
func WithOtelCollector(c *otel.Collector) Option {
	return func(r *Runtime) {
		r.otelCollector = c
	}
}

// WithLogsDir sets the directory where Envoy logs will be written.
// If this option is set, logs will be piped to files in the format
// envoy.<pid>.<pipe>.log in the specified directory.
func WithLogsDir(dir string) Option {
	return func(r *Runtime) {
		r.logsDir = dir
	}
}

type Runtime struct {
	EnvoyPath           string
	BootstrapConfigYAML string
	Release             ReleaseDownloader
	Cluster             string
	// Args are additional arguments to pass to Envoy.
	Args []string

	stopCh        chan struct{}
	cmd           *exec.Cmd
	logs          logs.LogsCollector
	envoyLogsDir  string
	otelCollector *otel.Collector
	goPluginDir   string
	adminHost     string
	drainTimeout  *time.Duration
	minDrainTime  *time.Duration
	logsDir       string
	nodeMetadata  *xdstypes.NodeMetadata

	mu     sync.RWMutex
	status RuntimeStatus
}

func (r *Runtime) setOptions(opts ...Option) {
	for _, opt := range opts {
		opt(r)
	}
	if r.Release == nil {
		r.Release = &LatestCachedRelease{
			Path: fmt.Sprintf("%s/envoy", config.ApoxyDir()),
		}
	}
	if r.Cluster == "" {
		r.Cluster = uuid.New().String()
	}
	if r.drainTimeout == nil {
		drainTimeout := defaultDrainTimeoutSeconds * time.Second
		r.drainTimeout = &drainTimeout
	}
	if r.minDrainTime == nil {
		minDrainTime := defaultDrainTimeoutSeconds * time.Second
		r.minDrainTime = &minDrainTime
	}
}

func (r *Runtime) run(ctx context.Context) error {
	id := uuid.New().String()

	nodeConfig := &corev3.Node{
		Id:      id,
		Cluster: r.Cluster,
	}
	if r.nodeMetadata != nil && !r.nodeMetadata.IsEmpty() {
		var err error
		nodeConfig.Metadata, err = r.nodeMetadata.ToStruct()
		if err != nil {
			return fmt.Errorf("failed to convert node metadata to map: %w", err)
		}
	}

	nodeJSON, err := protojson.Marshal(nodeConfig) // Must use protojson.Marshal to hide non-json fields.
	if err != nil {
		return fmt.Errorf("failed to marshal node config to JSON: %w", err)
	}

	configYAML := fmt.Sprintf(`node: %s`, string(nodeJSON))
	log.Infof("envoy YAML config: %s", configYAML)

	// Start OpenTelemetry collector if configured
	if r.otelCollector != nil {
		log.Infof("Starting OpenTelemetry collector before Envoy")
		if err := r.otelCollector.Start(ctx); err != nil {
			return fmt.Errorf("failed to start OpenTelemetry collector: %w", err)
		}
	}

	args := []string{
		"--config-yaml", configYAML,
	}

	if r.BootstrapConfigYAML != "" {
		f, err := os.CreateTemp("", "bootstrap-*.yaml")
		if err != nil {
			return fmt.Errorf("failed to create bootstrap config file: %w", err)
		}
		if _, err := f.WriteString(r.BootstrapConfigYAML); err != nil {
			return fmt.Errorf("failed to write bootstrap config file: %w", err)
		}
		args = append(args, "-c", f.Name())
	}

	rCtx, cancel := context.WithCancelCause(ctx)
	if r.logs != nil {
		go func() {
			err := r.logs.CollectAccessLogs(ctx, accessLogsPath)
			if err != nil {
				log.Errorf("failed to collect access logs: %v", err)
				cancel(fmt.Errorf("access logs collector failed: %v", err))
			}
		}()
		go func() {
			err := r.logs.CollectTaps(ctx, tapsPath)
			if err != nil {
				cancel(fmt.Errorf("taps collector failed: %v", err))
				log.Errorf("failed to collect taps: %v", err)
			}
		}()
	}

	runDir := os.TempDir()
	if r.goPluginDir != "" {
		log.Infof("linking go plugin directory %s to runDir %s", r.goPluginDir, runDir)
		// Link the Go plugin directory to the run directory.
		_, err := os.Lstat(filepath.Join(runDir, "go"))
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to check if go plugin directory symlink exists: %w", err)
		} else if err == nil {
			if err := os.Remove(filepath.Join(runDir, "go")); err != nil {
				return fmt.Errorf("failed to remove existing go plugin directory symlink: %w", err)
			}
		}

		if err := os.Symlink(r.goPluginDir, filepath.Join(runDir, "go")); err != nil {
			return fmt.Errorf("failed to symlink go plugin directory: %w", err)
		}
	}

	args = append(args, "--drain-time-s", strconv.Itoa(int(r.drainTimeout.Seconds())))
	args = append(args, r.Args...)
	r.cmd = exec.CommandContext(rCtx, r.envoyPath(), args...)
	r.cmd.Dir = runDir

	if r.envoyLogsDir != "" {
		// Create logs directory if it doesn't exist
		if err := os.MkdirAll(r.envoyLogsDir, 0755); err != nil {
			return fmt.Errorf("failed to create logs directory: %w", err)
		}

		// Create a temporary file for stdout and stderr
		// We'll rename these files after the process starts and we have the PID
		tmpStdoutFile, err := os.CreateTemp(r.envoyLogsDir, "envoy.stdout.*")
		if err != nil {
			return fmt.Errorf("failed to create temporary stdout file: %w", err)
		}
		tmpStderrFile, err := os.CreateTemp(r.envoyLogsDir, "envoy.stderr.*")
		if err != nil {
			tmpStdoutFile.Close()
			os.Remove(tmpStdoutFile.Name())
			return fmt.Errorf("failed to create temporary stderr file: %w", err)
		}

		defer tmpStdoutFile.Close()
		defer tmpStderrFile.Close()
		r.cmd.Stdout = io.MultiWriter(os.Stdout, tmpStdoutFile)
		r.cmd.Stderr = io.MultiWriter(os.Stderr, tmpStderrFile)

		if err := r.cmd.Start(); err != nil {
			os.Remove(tmpStdoutFile.Name())
			os.Remove(tmpStderrFile.Name())
			return fmt.Errorf("failed to start envoy: %w", err)
		}

		pid := r.cmd.Process.Pid
		log.Infof("envoy started with PID %d", pid)
		stdoutLogPath := filepath.Join(r.envoyLogsDir, fmt.Sprintf("envoy.%d.stdout.log", pid))
		stderrLogPath := filepath.Join(r.envoyLogsDir, fmt.Sprintf("envoy.%d.stderr.log", pid))

		// Rename the temporary files to their final names
		if err := os.Rename(tmpStdoutFile.Name(), stdoutLogPath); err != nil {
			log.Errorf("failed to rename stdout log file: %v", err)
			os.Remove(tmpStdoutFile.Name())
		}
		if err := os.Rename(tmpStderrFile.Name(), stderrLogPath); err != nil {
			log.Errorf("failed to rename stderr log file: %v", err)
			os.Remove(tmpStderrFile.Name())
		}
	} else {
		// Default behavior: pipe to os.Stdout and os.Stderr
		r.cmd.Stdout = os.Stdout
		r.cmd.Stderr = os.Stderr
		if err := r.cmd.Start(); err != nil {
			return fmt.Errorf("failed to start envoy: %w", err)
		}
	}

	r.mu.Lock()
	p, err := process.NewProcess(int32(r.cmd.Process.Pid))
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to find envoy process: %w", err)
	}
	ctime, err := p.CreateTimeWithContext(rCtx)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to get envoy process create time: %w", err)
	}
	r.status.StartedAt = time.Unix(0, ctime*int64(time.Millisecond)).UTC() // Convert from milliseconds to seconds.
	r.status.Running = true
	r.status.Starting = false
	r.mu.Unlock()

	// Restart envoy if it exits.
	if err := r.cmd.Wait(); err != nil {
		return fmt.Errorf("envoy exited with error: %w", err)
	}

	r.mu.Lock()
	r.status.Running = false
	r.status.ProcState = r.cmd.ProcessState
	r.mu.Unlock()

	return nil
}

// envoyPath returns the path to the Envoy binary. If EnvoyPath is set, it will
// be used. Otherwise, the binary will be downloaded and cached in the user's
// home directory.
func (r *Runtime) envoyPath() string {
	if r.EnvoyPath != "" {
		return r.EnvoyPath
	}
	return fmt.Sprintf("%s/envoy/%s/envoy", config.ApoxyDir(), r.Release.String())
}

// vendorEnvoyIfNotExists vendors the Envoy binary for the release if it does
// not exist.
func (r *Runtime) vendorEnvoyIfNotExists(ctx context.Context) error {
	if _, err := os.Stat(r.envoyPath()); err == nil {
		return nil
	}

	// Download the Envoy binary for the release.
	bin, err := r.Release.DownloadBinary(ctx)
	if err != nil {
		return fmt.Errorf("failed to download envoy: %w", err)
	}
	defer bin.Close()

	// Extract the Envoy binary.
	if err := os.MkdirAll(filepath.Dir(r.envoyPath()), 0755); err != nil {
		return fmt.Errorf("failed to create envoy directory: %w", err)
	}
	w, err := os.OpenFile(r.envoyPath(), os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("failed to open envoy: %w", err)
	}
	defer w.Close()
	if _, err := io.Copy(w, bin); err != nil {
		return fmt.Errorf("failed to copy envoy: %w", err)
	}
	if err := os.Chmod(r.envoyPath(), 0755); err != nil {
		return fmt.Errorf("failed to chmod envoy: %w", err)
	}

	return nil
}

// FatalError is an error that should cause the runtime to exit.
type FatalError struct {
	Err error
}

// Error implements the error interface.
func (e FatalError) Error() string {
	return e.Err.Error()
}

// Start starts the Envoy binary.
func (r *Runtime) Start(ctx context.Context, opts ...Option) error {
	status := r.RuntimeStatus()
	if status.Starting || status.Running {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.Starting = true

	r.setOptions(opts...)

	log.Infof("preparing envoy %s", r.Release)

	if err := r.vendorEnvoyIfNotExists(ctx); err != nil {
		return FatalError{Err: fmt.Errorf("failed to vendor envoy: %w", err)}
	}

	r.stopCh = make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Infof("context done")
			case <-r.stopCh:
				log.Infof("envoy stopped")
				return
			default:
			}

			if err := r.run(ctx); err != nil {
				log.Errorf("envoy exited with error: %v", err)
			}

			select {
			case <-ctx.Done():
				log.Infof("context done")
			case <-r.stopCh:
				log.Infof("envoy stopped")
				return
			default: // Restart envoy.
			}
		}
	}()

	return nil
}

// postEnvoyAdminAPI sends a POST request to the Envoy admin API.
func (r *Runtime) postEnvoyAdminAPI(path string) error {
	if r.cmd == nil {
		return errors.New("envoy not running")
	}
	if r.adminHost == "" {
		return errors.New("envoy admin host not set")
	}
	resp, err := http.Post("http://"+r.adminHost+"/"+path, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	return nil
}

// getTotalConnections retrieves the total number of open connections from Envoy's server.total_connections stat.
func (r *Runtime) getTotalConnections() (*int, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s//stats?filter=^server\\.total_connections$&format=json",
		r.adminHost))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	// Define struct to decode JSON response into; expecting a single stat in the response in the format:
	// {"stats":[{"name":"server.total_connections","value":123}]}
	var jsonData *struct {
		Stats []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"stats"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jsonData); err != nil {
		return nil, err
	}

	if len(jsonData.Stats) == 0 {
		return nil, fmt.Errorf("no stats found")
	}
	c := jsonData.Stats[0].Value

	log.Infof("total connections: %d", c)

	return &c, nil
}

// Shutdown gracefully drains connections and shuts down the Envoy process.
func (r *Runtime) Shutdown(ctx context.Context) error {
	if r.cmd == nil {
		return nil
	}

	log.Infof("shutting down envoy with drain timeout %s", r.drainTimeout)

	startDrain := time.Now()

	if err := r.postEnvoyAdminAPI("healthcheck/fail"); err != nil {
		log.Errorf("error failing active health checks: %v", err)
	}

	if err := r.postEnvoyAdminAPI("drain_listeners?graceful&skip_exit"); err != nil {
		log.Errorf("error initiating graceful drain: %v", err)
	}

	for {
		conn, err := r.getTotalConnections()
		if err != nil {
			log.Errorf("error getting total connections: %v", err)
		}

		if time.Since(startDrain) > *r.drainTimeout {
			log.Infof("drain timeout reached")
			break
		} else if conn != nil && *conn <= 0 &&
			// Only if we reached the minimum drain time - might still receive new connections.
			time.Since(startDrain) > *r.minDrainTime {
			log.Infof("all connections drained")
			break
		}

		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			log.Infof("context done while draining")
			break
		}
	}

	stopOnce := sync.OnceValue(func() error {
		close(r.stopCh)
		if r.otelCollector != nil {
			if err := r.otelCollector.Stop(ctx); err != nil {
				log.Errorf("error shutting down otel collector: %v", err)
			}
		}

		if err := r.postEnvoyAdminAPI("quitquitquit"); err != nil {
			log.Errorf("error posting to quitquitquit: %v", err)
		}

		exitCh := make(chan error)
		go func() {
			exitCh <- r.cmd.Wait()
		}()

		select {
		case err := <-exitCh:
			if err != nil {
				exitErr, ok := err.(*exec.ExitError)
				if ok {
					return fmt.Errorf("envoy process exited with status %d", exitErr.ExitCode())
				}
				return err
			}
			return nil
		case <-ctx.Done():
			log.Infof("context done while waiting for envoy process to exit")
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}

		if err := r.cmd.Process.Kill(); err != nil {
			return err
		}
		return errors.New("envoy process killed")
	})
	return stopOnce()
}

type RuntimeStatus struct {
	StartedAt time.Time
	Starting  bool
	Running   bool
	ProcState *os.ProcessState
}

// RuntimeStatus returns the status of the Envoy process.
func (r *Runtime) RuntimeStatus() RuntimeStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}
