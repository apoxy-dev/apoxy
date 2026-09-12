package envoy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/process"
	"google.golang.org/protobuf/encoding/protojson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

	// DefaultVersion is the Envoy release that backplane images bake in and
	// that the runtime downloads. The Envoy version must not float, because a
	// new minor release can break the Go filter. Bump it only after a soak
	// test of the new release.
	DefaultVersion = "v1.35.13"

	accessLogsPath = "/var/log/accesslogs"
	tapsPath       = "/var/log/taps"

	defaultDrainTimeoutSeconds = 30

	// metricsFlushTimeout bounds the last push of the runtime metrics on
	// shutdown.
	metricsFlushTimeout = 5 * time.Second
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
		r.tel.logs = c
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
		r.tel.otelCollector = c
	}
}

// WithIdentity names the Proxy and the replica this runtime belongs to. Every
// metric datapoint carries the names as attributes. The project ID is empty
// outside the hosted platform.
func WithIdentity(proxy, replica, projectID string) Option {
	return func(r *Runtime) {
		r.tel.identity = Identity{Proxy: proxy, Replica: replica, ProjectID: projectID}
	}
}

// WithLimits sets the configured ceilings of the Envoy process. The runtime
// publishes them as gauges next to the values Envoy reports.
func WithLimits(l Limits) Option {
	return func(r *Runtime) {
		r.tel.limits = l
	}
}

// WithOTLPMetricSink sends the runtime metrics to the OpenTelemetry collector
// at addr ("host:port"). An empty address leaves the OTLP export off.
func WithOTLPMetricSink(addr string) Option {
	return func(r *Runtime) {
		r.tel.otlpSinkAddr = addr
	}
}

// Identity names the Proxy and the replica the Envoy process belongs to.
type Identity struct {
	// Proxy is the name of the Proxy object.
	Proxy string
	// Replica is the name of the replica.
	Replica string
	// ProjectID is the Apoxy project. It is empty outside the hosted platform.
	ProjectID string
}

type Runtime struct {
	EnvoyPath           string
	BootstrapConfigYAML string
	Release             ReleaseDownloader
	Cluster             string
	// Args are additional arguments to pass to Envoy.
	Args []string

	stopCh       chan struct{}
	cmd          *exec.Cmd
	goPluginDir  string
	adminHost    string
	drainTimeout *time.Duration
	minDrainTime *time.Duration
	nodeMetadata *xdstypes.NodeMetadata

	// tel holds everything the backplane observes about the process.
	tel telemetry

	mu     sync.RWMutex
	status RuntimeStatus
	// pid is the process ID of the running Envoy process, or zero.
	pid int
	// exited is closed when the wait on the Envoy process returns. It is nil
	// until the first process starts.
	exited chan struct{}
}

// Configure applies options to the runtime before it starts. Metrics read the
// values at collection time, so the caller sets identity and limits once.
func (r *Runtime) Configure(opts ...Option) {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(r)
	}
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
	if meta := r.exitMetadata(); meta != nil && !meta.IsEmpty() {
		var err error
		nodeConfig.Metadata, err = meta.ToStruct()
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
	if r.tel.otelCollector != nil {
		log.Infof("Starting OpenTelemetry collector before Envoy")
		if err := r.tel.otelCollector.Start(ctx); err != nil {
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
	if r.tel.logs != nil {
		go func() {
			err := r.tel.logs.CollectAccessLogs(ctx, accessLogsPath)
			if err != nil {
				log.Errorf("failed to collect access logs: %v", err)
				cancel(fmt.Errorf("access logs collector failed: %v", err))
			}
		}()
		go func() {
			err := r.tel.logs.CollectTaps(ctx, tapsPath)
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

	// Wrap subprocess output in structured log entries.
	r.cmd.Stdout = log.NewSubprocessWriter("envoy", log.InfoLevel)
	r.cmd.Stderr = log.NewSubprocessWriter("envoy", log.WarnLevel)
	if err := r.cmd.Start(); err != nil {
		r.recordExit(nil, err, time.Time{})
		return fmt.Errorf("failed to start envoy: %w", err)
	}

	pid := r.cmd.Process.Pid
	log.Infof("envoy started with PID %d", pid)
	// Read the OOM kill count outside the lock. The next exit compares against
	// it to tell an OOM kill from any other kill.
	kills, killsKnown := defaultCgroupReader().oomKills()
	exited := make(chan struct{})

	r.mu.Lock()
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to find envoy process: %w", err)
	}
	ctime, err := p.CreateTimeWithContext(rCtx)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to get envoy process create time: %w", err)
	}
	startedAt := time.Unix(0, ctime*int64(time.Millisecond)).UTC() // Convert from milliseconds to seconds.
	r.status.StartedAt = startedAt
	r.status.Running = true
	r.status.Starting = false
	r.pid = pid
	r.exited = exited
	r.mu.Unlock()

	r.tel.startProcess(kills, killsKnown)

	// The kernel counted the connections it aborted and refused while Envoy
	// was down. Close that window now that the next process runs.
	r.closeDownWindow(ctx)

	// The admin interface answers only while the process runs, so the sampler
	// stops with it.
	stopSampler := r.startSampler(rCtx)

	// Always record the exit, also when Wait reports an error. The caller
	// restarts Envoy. Only this goroutine waits on the process, so that the
	// process state has one reader.
	waitErr := r.cmd.Wait()
	stopSampler()
	state := r.cmd.ProcessState
	r.recordExit(state, waitErr, startedAt)
	r.logExit(ctx, pid)
	close(exited)

	if waitErr != nil {
		return fmt.Errorf("envoy exited with error: %w", waitErr)
	}

	return nil
}

// exitMetadata returns the node metadata with the restart count and the last
// exit of the Envoy process. The apiserver copies both into the replica status.
func (r *Runtime) exitMetadata() *xdstypes.NodeMetadata {
	if r.nodeMetadata == nil {
		return nil
	}

	meta := r.nodeMetadata.Clone()

	r.mu.RLock()
	defer r.mu.RUnlock()

	meta.EnvoyRestarts = int32(r.status.Restarts)
	if e := r.status.LastExit; e != nil {
		meta.LastEnvoyExit = &xdstypes.NodeEnvoyExit{
			At:     metav1.NewTime(e.At),
			Reason: e.Reason,
			Code:   e.Code,
		}
	}

	return meta
}

// logExit writes one line that describes how Envoy exited.
func (r *Runtime) logExit(ctx context.Context, pid int) {
	r.mu.RLock()
	e := r.status.LastExit
	restarts := r.status.Restarts
	r.mu.RUnlock()
	if e == nil {
		return
	}

	release := ""
	if r.Release != nil {
		release = r.Release.String()
	}

	attrs := []slog.Attr{
		slog.String("reason", e.Reason),
		slog.String("code", e.Code),
		slog.Bool("core_dump", coreDump(e.ProcState)),
		slog.Duration("uptime", e.Uptime),
		slog.Any("requests_in_flight", int64Value(e.RequestsInFlight)),
		slog.Any("connections", int64Value(e.Connections)),
		slog.Duration("sample_age", e.SampleAge),
		slog.Int64("connections_aborted", e.ConnectionsAborted),
		slog.Int64("connections_refused", e.ConnectionsRefused),
		slog.Int("pid", pid),
		slog.Int("restarts", restarts),
		slog.String("release", release),
	}

	level := slog.LevelError
	if e.Reason == ExitReasonExit && e.Code == "0" {
		level = slog.LevelInfo
	}
	slog.Default().LogAttrs(ctx, level, "Envoy exited", attrs...)
}

// int64Value returns the value v points to, or nil when v is nil.
func int64Value(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// procStateString describes how the process exited, for example "exit status
// 1" or "signal: killed".
func procStateString(state *os.ProcessState) string {
	if state == nil {
		return "unknown"
	}
	return state.String()
}

// Exit reasons the runtime records. The code is the decimal exit status for
// ExitReasonExit, the signal name for ExitReasonSignal and ExitReasonOOMKill,
// and empty for ExitReasonStartFailed.
const (
	ExitReasonExit        = "exit"
	ExitReasonSignal      = "signal"
	ExitReasonOOMKill     = "oom_kill"
	ExitReasonStartFailed = "start_failed"
)

// signalNames maps the signals Envoy dies from to their name. The names must
// not come from Signal.String(), which returns a description such as "killed".
var signalNames = map[syscall.Signal]string{
	syscall.SIGABRT: "SIGABRT",
	syscall.SIGALRM: "SIGALRM",
	syscall.SIGBUS:  "SIGBUS",
	syscall.SIGFPE:  "SIGFPE",
	syscall.SIGHUP:  "SIGHUP",
	syscall.SIGILL:  "SIGILL",
	syscall.SIGINT:  "SIGINT",
	syscall.SIGKILL: "SIGKILL",
	syscall.SIGPIPE: "SIGPIPE",
	syscall.SIGQUIT: "SIGQUIT",
	syscall.SIGSEGV: "SIGSEGV",
	syscall.SIGSYS:  "SIGSYS",
	syscall.SIGTERM: "SIGTERM",
	syscall.SIGTRAP: "SIGTRAP",
	syscall.SIGXCPU: "SIGXCPU",
	syscall.SIGXFSZ: "SIGXFSZ",
}

// signalName returns the name of sig, for example "SIGKILL".
func signalName(sig syscall.Signal) string {
	if name, ok := signalNames[sig]; ok {
		return name
	}
	return "SIG" + strconv.Itoa(int(sig))
}

// exitReason describes how the process ended. A nil state means the process
// never started.
func exitReason(state *os.ProcessState) (reason, code string) {
	if state == nil {
		return ExitReasonStartFailed, ""
	}

	ws, ok := state.Sys().(syscall.WaitStatus)
	if !ok {
		return ExitReasonExit, strconv.Itoa(state.ExitCode())
	}
	if ws.Signaled() {
		return ExitReasonSignal, signalName(ws.Signal())
	}

	return ExitReasonExit, strconv.Itoa(ws.ExitStatus())
}

// coreDump reports whether the process wrote a core dump.
func coreDump(state *os.ProcessState) bool {
	if state == nil {
		return false
	}
	ws, ok := state.Sys().(syscall.WaitStatus)
	return ok && ws.CoreDump()
}

// recordExit records the exit of the Envoy process in the runtime status.
// startedAt is the start time of the process, or the zero time when the
// process never started.
func (r *Runtime) recordExit(state *os.ProcessState, err error, startedAt time.Time) {
	// Read the counters outside the lock. Both reads open a file.
	kills, killsKnown := defaultCgroupReader().oomKills()
	var down *tcpCounters
	if _, nr := systemReaders(); nr != nil {
		if c, cerr := nr.TCPCounters(); cerr == nil {
			down = &c
		}
	}

	last, lastTCP, oomKilled := r.tel.exitState(kills, killsKnown)

	reason, code := exitReason(state)
	// The cgroup OOM killer sends SIGKILL, which looks like any other kill.
	// Only a higher OOM count tells the two apart.
	if reason == ExitReasonSignal && code == "SIGKILL" && oomKilled {
		reason = ExitReasonOOMKill
	}

	e := &ExitInfo{
		At:        time.Now().UTC(),
		ProcState: state,
		Err:       err,
		Reason:    reason,
		Code:      code,
	}
	if !startedAt.IsZero() {
		e.Uptime = e.At.Sub(startedAt)
	}
	if last != nil {
		e.RequestsInFlight = &last.RequestsInFlight
		e.Connections = &last.Connections
		e.SampleAge = e.At.Sub(last.At)
	}
	// The kernel tears the connections of the process down before the parent
	// reaps it, so the count runs from the last sample, not from now. This is
	// a floor. The next start counts the whole window. EstabResets alone
	// counts one torn down connection one time.
	if down != nil && lastTCP != nil {
		e.ConnectionsAborted = delta(down.EstabResets, lastTCP.EstabResets)
	}

	var w *restartWindow
	if down != nil {
		w = &restartWindow{
			LastSample: lastTCP,
			AtExit:     *down,
			At:         e.At,
		}
	}
	r.tel.setWindow(w)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.status.Running = false
	r.status.ProcState = state
	r.status.LastExit = e
	if r.status.ExitCounts == nil {
		r.status.ExitCounts = make(map[ExitKey]int64)
	}
	r.status.ExitCounts[ExitKey{Reason: reason, Code: code}]++

	r.pid = 0
}

// restartWindow holds the kernel TCP counters that bound the time the Envoy
// process was gone.
type restartWindow struct {
	// LastSample is the newest read taken while the process still ran. It is
	// nil when the sampler took no read.
	LastSample *tcpCounters
	// AtExit is the read taken when the wait on the process returned.
	AtExit tcpCounters
	// At is when the exit was recorded.
	At time.Time
}

// closeDownWindow counts the connections the kernel aborted and refused while
// Envoy was gone into the last exit record. It runs right after the next
// process starts, which is before Envoy binds its listeners. No connection
// reaches the established state while Envoy is gone, so every reset in the
// window belongs to the connections the exit tore down.
func (r *Runtime) closeDownWindow(ctx context.Context) {
	_, nr := systemReaders()
	if nr == nil {
		return
	}

	w := r.tel.restartWindow()
	if w == nil {
		return
	}

	now, err := nr.TCPCounters()
	if err != nil {
		return
	}
	r.tel.clearWindow()

	r.mu.Lock()
	if r.status.LastExit == nil {
		r.mu.Unlock()
		return
	}

	// Publish a copy. Readers keep the pointer they already took.
	e := *r.status.LastExit
	if w.LastSample != nil {
		e.ConnectionsAborted = delta(now.EstabResets, w.LastSample.EstabResets)
	}
	e.ConnectionsRefused = delta(now.OutRsts, w.AtExit.OutRsts)
	r.status.LastExit = &e
	r.mu.Unlock()

	slog.Default().LogAttrs(ctx, slog.LevelInfo, "Envoy restart window closed",
		slog.Int64("connections_aborted", e.ConnectionsAborted),
		slog.Int64("connections_refused", e.ConnectionsRefused),
		slog.Duration("down_window", time.Since(w.At)),
	)
}

// delta returns the increase of a kernel counter. A counter that wrapped or
// was reset gives zero.
func delta(now, before int64) int64 {
	if now < before {
		return 0
	}
	return now - before
}

// recordRestart counts one more start of the Envoy process.
func (r *Runtime) recordRestart() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.Restarts++
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

	// Read the published digest first. Releases that publish no digest give an
	// empty value and the download is not checked.
	var want string
	if cd, ok := r.Release.(ChecksumDownloader); ok {
		var err error
		if want, err = cd.DownloadChecksum(ctx); err != nil {
			return fmt.Errorf("failed to get envoy checksum: %w", err)
		}
	}

	// Download the Envoy binary for the release.
	bin, err := r.Release.DownloadBinary(ctx)
	if err != nil {
		return fmt.Errorf("failed to download envoy: %w", err)
	}
	defer bin.Close()

	path := r.envoyPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create envoy directory: %w", err)
	}

	// Write to a temporary file in the same directory and hash the bytes as
	// they arrive. The final path must never hold an unchecked or partial
	// binary.
	tmp, err := os.CreateTemp(dir, ".envoy-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary envoy file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath) // Does nothing after a successful rename.
	}()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), bin); err != nil {
		return fmt.Errorf("failed to copy envoy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close envoy: %w", err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if want != "" {
		if got != want {
			return fmt.Errorf("envoy checksum mismatch: expected %s, actual %s", want, got)
		}
		log.Infof("Verified Envoy download against published checksum %s", got)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("failed to chmod envoy: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to move envoy into place: %w", err)
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
	r.status.Starting = true
	r.setOptions(opts...)
	r.mu.Unlock()

	log.Infof("preparing envoy %s", r.Release)

	// The download takes minutes on the first start. A metrics scrape reads
	// the status through the same lock, so the download must not hold it.
	// Starting stays true on failure, which keeps the caller from retrying.
	if err := r.vendorEnvoyIfNotExists(ctx); err != nil {
		return FatalError{Err: fmt.Errorf("failed to vendor envoy: %w", err)}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopCh = make(chan struct{})
	go func() {
		runs := 0
		for {
			select {
			case <-ctx.Done():
				log.Infof("context done")
				return
			case <-r.stopCh:
				log.Infof("envoy stopped")
				return
			default:
			}

			if runs > 0 {
				r.recordRestart()
			}
			runs++

			if err := r.run(ctx); err != nil {
				log.Errorf("envoy exited with error: %v", err)
			}

			// Restart envoy unless we are shutting down. The 1s pause keeps a
			// persistently failing envoy from busy-looping (and spamming logs).
			select {
			case <-ctx.Done():
				log.Infof("context done")
				return
			case <-r.stopCh:
				log.Infof("envoy stopped")
				return
			case <-time.After(1 * time.Second):
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

drain:
	for {
		conn, err := r.getTotalConnections()
		if err != nil {
			log.Errorf("error getting total connections: %v", err)
		} else if conn != nil {
			log.Infof("draining, total connections: %d", *conn)
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
			break drain
		}
	}

	stopOnce := sync.OnceValue(func() error {
		close(r.stopCh)
		if m := r.metricsIfStarted(); m != nil {
			// The caller may shut down with a context that is already done.
			// The last push of the metrics needs a live one.
			flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), metricsFlushTimeout)
			err := m.Shutdown(flushCtx)
			cancel()
			if err != nil {
				log.Errorf("error shutting down runtime metrics: %v", err)
			}
		}
		if r.tel.otelCollector != nil {
			if err := r.tel.otelCollector.Stop(ctx); err != nil {
				log.Errorf("error shutting down otel collector: %v", err)
			}
		}

		if err := r.postEnvoyAdminAPI("quitquitquit"); err != nil {
			log.Errorf("error posting to quitquitquit: %v", err)
		}

		// Only run() waits on the process. This goroutine waits for run() to
		// report the exit instead, so that the process state has one reader.
		select {
		case <-r.exitedCh():
			return r.lastExitError()
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

// exitedCh returns the channel that run() closes when the Envoy process ends.
// It is nil until the first process starts, which blocks the caller until its
// own timeout.
func (r *Runtime) exitedCh() <-chan struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.exited
}

// lastExitError describes the last exit of the Envoy process as an error, or
// nil when the process exited cleanly.
func (r *Runtime) lastExitError() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.status.LastExit == nil || r.status.LastExit.Err == nil {
		return nil
	}

	err := r.status.LastExit.Err
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("envoy process exited with status %d", exitErr.ExitCode())
	}

	return err
}

// ExitInfo records the last exit of the Envoy process.
type ExitInfo struct {
	// At is the time the exit was recorded.
	At time.Time
	// ProcState is the state of the exited process. It is nil if the process
	// never started.
	ProcState *os.ProcessState
	// Err is the error returned by the wait on the process, if any.
	Err error
	// Reason is one of exit, signal, oom_kill and start_failed.
	Reason string
	// Code is the decimal exit status for an exit, the signal name for a
	// signal and an OOM kill, and empty for a failed start.
	Code string
	// Uptime is how long the process ran.
	Uptime time.Duration
	// RequestsInFlight is the last sampled number of active downstream
	// requests. It is nil when no sample was taken.
	RequestsInFlight *int64
	// Connections is the last sampled number of active downstream connections.
	// It is nil when no sample was taken.
	Connections *int64
	// SampleAge is how old the sample was when the process exited.
	SampleAge time.Duration
	// ConnectionsAborted counts the established connections the kernel tore
	// down when the process died. The value at the exit is a floor, because
	// the kernel resets the sockets after the parent reaps the process. It
	// becomes final when the next process starts.
	ConnectionsAborted int64
	// ConnectionsRefused counts the connection attempts the kernel answered
	// with a reset while Envoy was gone. It becomes final when the next
	// process starts.
	ConnectionsRefused int64
}

// ExitKey names one kind of exit. The set of keys is bounded by the reason
// vocabulary and the exit status range.
type ExitKey struct {
	// Reason is one of exit, signal, oom_kill and start_failed.
	Reason string
	// Code is the exit status or the signal name.
	Code string
}

type RuntimeStatus struct {
	StartedAt time.Time
	Starting  bool
	Running   bool
	ProcState *os.ProcessState
	// LastExit is the last recorded exit of the Envoy process. It is nil until
	// the process exits for the first time.
	LastExit *ExitInfo
	// Restarts counts how many times the runtime started Envoy again after an
	// exit.
	Restarts int
	// ExitCounts counts the exits of each reason and code.
	ExitCounts map[ExitKey]int64
}

// RuntimeStatus returns the status of the Envoy process.
func (r *Runtime) RuntimeStatus() RuntimeStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s := r.status
	// The caller must not observe later exits through the shared map.
	if r.status.ExitCounts != nil {
		s.ExitCounts = make(map[ExitKey]int64, len(r.status.ExitCounts))
		for k, v := range r.status.ExitCounts {
			s.ExitCounts[k] = v
		}
	}

	return s
}
