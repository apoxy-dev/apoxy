package envoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/process"

	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/backplane/logs"
	"github.com/apoxy-dev/apoxy/pkg/backplane/otel"
	"github.com/apoxy-dev/apoxy/pkg/log"

	_ "github.com/apoxy-dev/apoxy/pkg/gateway/xds/extensions"
)

const (
	githubURL = "github.com/envoyproxy/envoy/releases/download"

	// DefaultVersion pins the Envoy release baked into backplane images and
	// downloaded at runtime. Envoy versions must never float: the 1.35.3 →
	// 1.38.x jump (picked up implicitly via GetLatestRelease when the
	// v0.11.22/23 images were built) regressed the golang filter with a
	// tcmalloc SIGSEGV on the cgo thread-adoption path (x_cgo_getstackbound
	// → pthread_getattr_np → calloc). 1.36.13 matched 1.35.13 (no crashes)
	// in a golang-filter soak under listener-reload churn, while 1.37.10 and
	// 1.38.8 crashed. Bump only after the same soak.
	DefaultVersion = "v1.36.13"

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

// WithDrainIdleExitQuietPeriod sets how long Envoy must stay idle before the
// drain ends early. Zero disables the idle exit.
func WithDrainIdleExitQuietPeriod(d time.Duration) Option {
	return func(r *Runtime) {
		r.idleQuietPeriod = d
	}
}

// WithDrainIdleExitTestPause holds the shutdown between the idle decision and
// the Envoy stop. It exists for tests only.
func WithDrainIdleExitTestPause(d time.Duration) Option {
	return func(r *Runtime) {
		r.idleTestPause = d
	}
}

// WithDrainPhaseHook is called on every drain phase change.
func WithDrainPhaseHook(f func(DrainPhase)) Option {
	return func(r *Runtime) {
		r.phaseHook = f
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

	cmd           *exec.Cmd
	logs          logs.LogsCollector
	envoyLogsDir  string
	otelCollector *otel.Collector
	goPluginDir   string
	adminHost     string
	drainTimeout  *time.Duration
	minDrainTime  *time.Duration
	logsDir       string

	idleQuietPeriod time.Duration
	idleTestPause   time.Duration
	phaseHook       func(DrainPhase)
	timeouts        shutdownTimeouts
	// stopTelemetryFn replaces the otel collector stop in tests.
	stopTelemetryFn func(context.Context) error
	// killFn replaces the SIGKILL in tests.
	killFn func(*os.Process) error
	// fenced is set once the backplane exits; Start never runs Envoy after it.
	fenced bool

	mu     sync.RWMutex
	status RuntimeStatus
	gen    *generation
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
	if r.timeouts == (shutdownTimeouts{}) {
		r.timeouts = defaultShutdownTimeouts
	}
}

func (r *Runtime) run(ctx context.Context, g *generation) error {
	id := uuid.New().String()
	configYAML := fmt.Sprintf(`node: { id: "%s", cluster: "%s" }`, id, r.Cluster)
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
	defer cancel(nil)
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
	cmd := exec.CommandContext(rCtx, r.envoyPath(), args...)
	cmd.Dir = runDir

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
		cmd.Stdout = io.MultiWriter(os.Stdout, tmpStdoutFile)
		cmd.Stderr = io.MultiWriter(os.Stderr, tmpStderrFile)

		if err := r.startProcess(g, cmd); err != nil {
			os.Remove(tmpStdoutFile.Name())
			os.Remove(tmpStderrFile.Name())
			return err
		}

		pid := cmd.Process.Pid
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
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := r.startProcess(g, cmd); err != nil {
			return err
		}
	}

	r.mu.Lock()
	// An unknown start time must not skip the wait below and orphan Envoy.
	r.status.StartedAt = time.Now().UTC()
	p, err := process.NewProcess(int32(cmd.Process.Pid))
	if err == nil {
		var ctime int64
		if ctime, err = p.CreateTimeWithContext(rCtx); err == nil {
			// Convert from milliseconds to seconds.
			r.status.StartedAt = time.Unix(0, ctime*int64(time.Millisecond)).UTC()
		}
	}
	r.status.Running = true
	r.status.Starting = false
	r.mu.Unlock()
	if err != nil {
		log.Errorf("failed to read envoy process start time: %v", err)
	}

	// Restart envoy if it exits.
	waitErr := cmd.Wait()
	// Record the exit even on error, or the reconciler sees a dead Envoy as running.
	r.mu.Lock()
	r.status.Running = false
	r.status.ProcState = cmd.ProcessState
	r.mu.Unlock()

	if waitErr != nil {
		return fmt.Errorf("envoy exited with error: %w", waitErr)
	}
	return nil
}

// startProcess starts cmd unless the generation is shutting down. The check
// and the start share r.mu, so a shutdown never misses a process.
func (r *Runtime) startProcess(g *generation, cmd *exec.Cmd) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g.shuttingDown {
		return errShuttingDown
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start envoy: %w", err)
	}
	r.cmd = cmd
	g.cmd = cmd
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
	r.mu.Lock()
	if r.fenced {
		r.mu.Unlock()
		return ErrShutDown
	}
	if r.status.Starting || r.status.Running || (r.gen != nil && !r.gen.isDone()) {
		r.mu.Unlock()
		return nil
	}
	r.status.Starting = true
	r.setOptions(opts...)
	g := newGeneration()
	r.gen = g
	phase := r.phaseHook
	r.mu.Unlock()
	if phase != nil {
		phase(DrainPhaseServing)
	}

	log.Infof("preparing envoy %s", r.Release)

	if err := r.vendorEnvoyIfNotExists(ctx); err != nil {
		g.closeExited()
		return FatalError{Err: fmt.Errorf("failed to vendor envoy: %w", err)}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if g.shuttingDown {
		g.closeExited()
		return nil
	}
	go r.supervise(ctx, g)

	return nil
}

// supervise runs Envoy and restarts it until the generation shuts down.
func (r *Runtime) supervise(ctx context.Context, g *generation) {
	defer g.closeExited()
	for {
		select {
		case <-ctx.Done():
			log.Infof("context done")
			return
		case <-g.stopCh:
			log.Infof("envoy stopped")
			return
		default: // Restart envoy.
		}

		if err := r.run(ctx, g); errors.Is(err, errShuttingDown) {
			log.Infof("envoy not restarted: shutting down")
			return
		} else if err != nil {
			log.Errorf("envoy exited with error: %v", err)
		}
	}
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
