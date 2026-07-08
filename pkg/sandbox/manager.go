//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manager is the tenant-neutral gVisor/runsc sandbox lifecycle runtime —
// the production implementation of [Runtime]. It pulls OCI images, builds
// per-sandbox OCI bundles, and drives `runsc create/start/kill/wait/
// delete` subprocesses that re-enter the same binary via [DispatchRunsc].
//
// It carries no agent-lineage, identity, trust, egress, or Kubernetes
// coupling: those live on clrk's internal/worker/sandbox wrapper, which
// embeds this Manager, adapts its CRD CreateRequest down to a [Spec], and
// re-adds the egress data path + OTLP stdio + persistent-state mounts. An
// external consumer (workerd-host) embeds this Manager directly.
type Manager struct {
	stateDir       string // runsc --root.
	rootDir        string // Per-sandbox netconfig + caller-supplied mount sources.
	imageStore     *ImageStore
	hostCgroupPath string // Absolute path of the host's own cgroup v2 dir (from InitHostCgroup).

	// logSinkFor, when set, supplies the per-sandbox stdio log sink at
	// Start. nil → the Sentry stdio log copy is discarded (the
	// caller-facing pipes in stdio mode are unaffected).
	logSinkFor func(id SandboxID) StdioSink

	// mu guards every map below.
	mu        sync.RWMutex
	sandboxes map[SandboxID]*Instance
	waiters   map[SandboxID]context.CancelFunc
	stdSinks  map[SandboxID]StdioSink
}

// ManagerConfig bundles the construction-time inputs of [NewManager].
type ManagerConfig struct {
	// StateDir is runsc's --root directory; one subdirectory per sandbox
	// keyed by container ID.
	StateDir string
	// RootDir holds per-sandbox netconfig (resolv.conf) and is the
	// conventional home for caller-supplied bind-mount sources.
	RootDir string
	// ImageStore pulls and extracts OCI images. Shared across all
	// sandboxes on this host.
	ImageStore *ImageStore
	// HostCgroupPath is the absolute path of the host's cgroup v2
	// directory as returned by [InitHostCgroup]. Required: Create fails
	// if it's empty because per-sandbox enforcement depends on being able
	// to mkdir under <HostCgroupPath>/system/<id>.
	HostCgroupPath string
	// LogSinkFor, when set, is called by Start to obtain the per-sandbox
	// stdio log sink (see [StdioSink]). Optional; nil discards the stdio
	// log copy.
	LogSinkFor func(id SandboxID) StdioSink
}

// Compile-time check that *Manager is the production [Runtime].
var _ Runtime = (*Manager)(nil)

// NewManager constructs the sandbox lifecycle manager.
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		stateDir:       cfg.StateDir,
		rootDir:        cfg.RootDir,
		imageStore:     cfg.ImageStore,
		hostCgroupPath: cfg.HostCgroupPath,
		logSinkFor:     cfg.LogSinkFor,
		sandboxes:      make(map[SandboxID]*Instance),
		waiters:        make(map[SandboxID]context.CancelFunc),
		stdSinks:       make(map[SandboxID]StdioSink),
	}
}

// EnsureImage pulls (or returns cached metadata for) ref via the
// manager's underlying ImageStore. Exposed so an embedder can resolve the
// extracted rootfs (e.g. to compute rootfs-dependent mounts) before
// building the [Spec] it hands to Create — the pull is singleflight-cached
// so the re-pull inside Create is free.
func (m *Manager) EnsureImage(ctx context.Context, ref string) (*ImageInfo, error) {
	return m.imageStore.EnsureImage(ctx, ref)
}

// ImageStore returns the manager's image store so callers that need the
// cached-refs query can reach it without crossing into private state.
func (m *Manager) ImageStore() *ImageStore { return m.imageStore }

// Create pulls the image, builds an OCI bundle, and runs `runsc create`
// to spawn the Sentry. The sandbox is left in the Ready phase for
// resident-pool use — Start is a separate call.
func (m *Manager) Create(ctx context.Context, spec Spec) (*Instance, error) {
	m.mu.Lock()
	if _, exists := m.sandboxes[spec.ID]; exists {
		m.mu.Unlock()
		return nil, ErrAlreadyExists
	}
	m.mu.Unlock()

	log := slog.With(slog.String("sandbox.id", string(spec.ID)))
	log.Info("Creating sandbox")

	imgInfo, err := m.imageStore.EnsureImage(ctx, spec.Image)
	if err != nil {
		return nil, fmt.Errorf("ensuring image: %w", err)
	}
	rootfs := imgInfo.RootFS

	// Allocate the per-sandbox /30 (gw + container IP). No real netns or
	// TAP under sentrystack — the Sentry's PluginStack is the only network
	// the sandbox sees; the host-side OCI runtime inherits the host
	// process's netns so an installed forwarder can dial 127.0.0.1. The
	// IPs only feed the init payload + resolv.conf.
	gw, sandboxIP, err := allocateIPs()
	if err != nil {
		return nil, fmt.Errorf("allocating sandbox IPs: %w", err)
	}

	// Unwinds in LIFO order on error; cleared on success.
	var cleanup []func()
	defer func() {
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}()
	pushCleanup := func(f func()) { cleanup = append(cleanup, f) }

	resolvPath, err := m.writeSandboxResolvConf(spec.ID, gw)
	if err != nil {
		return nil, fmt.Errorf("staging sandbox resolv.conf: %w", err)
	}
	pushCleanup(func() { m.removeSandboxNetConfig(spec.ID) })

	// The resolv.conf mount is core-owned (it depends on the gateway we
	// just allocated); the embedder's extra mounts (trust, state) ride in
	// spec.Mounts.
	mounts := append([]Mount{resolvMountSpec(resolvPath)}, spec.Mounts...)

	args := resolveProcessArgs(spec.Command, spec.Args, imgInfo.Entrypoint)
	ociSpec := buildSpec(string(spec.ID), rootfs, args, spec.Env, spec.CPUMillis, spec.MemBytes, mounts, spec.Annotations)

	bundleDir, err := m.ensureRunscBundleDir(spec.ID)
	if err != nil {
		return nil, err
	}
	pushCleanup(func() { m.removeRunscBundleDir(spec.ID) })
	if err := writeConfigJSON(bundleDir, ociSpec); err != nil {
		return nil, fmt.Errorf("writing OCI bundle: %w", err)
	}

	sb := &Instance{
		ID:        spec.ID,
		Phase:     SandboxReady,
		RootFS:    rootfs,
		SandboxIP: sandboxIP,
		GatewayIP: gw,
		// Stash before buildSandboxInitStr below so the sealed initStr carries
		// the inbound listen addr + fd index and the control forward/host addr; a
		// value arriving after Create would never reach the Sentry's PreInit.
		// Empty inbound = egress-only; empty control = no control plane.
		inboundListenAddr:  spec.InboundListenAddr,
		controlForwardAddr: spec.ControlForwardAddr,
		controlHostAddr:    spec.ControlHostAddr,
		CreatedAt:          time.Now(),
	}

	if err := wireSandboxStdio(sb, spec.Stdio); err != nil {
		return nil, err
	}
	pushCleanup(sb.closeStdio)

	initStr, err := buildSandboxInitStr(sb, spec.Egress)
	if err != nil {
		return nil, fmt.Errorf("building sentrystack init payload: %w", err)
	}
	sb.initStr = initStr

	// LIFO defer order closes cgroupFD before the cleanup chain rmdirs the
	// directory — rmdir on a cgroup with an open dir FD returns EBUSY.
	cgroupFD, err := createSandboxCgroup(m.hostCgroupPath, spec.ID, spec.CPUMillis, spec.MemBytes)
	if err != nil {
		return nil, fmt.Errorf("creating sandbox cgroup: %w", err)
	}
	defer func() { _ = cgroupFD.Close() }()
	pushCleanup(func() { _ = removeSandboxCgroup(m.hostCgroupPath, spec.ID) })

	if err := runscCreate(ctx, runscCreateOpts{
		id:          string(spec.ID),
		rootDir:     m.stateDir,
		bundleDir:   bundleDir,
		initStr:     initStr,
		stdin:       sb.stdinChild,
		stdout:      sb.stdoutChild,
		stderr:      sb.stderrChild,
		cgroupDirFD: cgroupFD,
	}); err != nil {
		return nil, fmt.Errorf("creating sandbox via runsc: %w", err)
	}

	cleanup = nil // success — keep all allocated resources.
	m.mu.Lock()
	m.sandboxes[spec.ID] = sb
	m.mu.Unlock()

	log.Info("Sandbox created")
	return sb, nil
}

// Start fires the Sentry's spec.Process. The user binary is running
// inside the sandbox after this returns.
func (m *Manager) Start(ctx context.Context, id SandboxID) error {
	m.mu.Lock()
	sb, ok := m.sandboxes[id]
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}

	log := slog.With(slog.String("sandbox.id", string(id)))

	var sink StdioSink
	if m.logSinkFor != nil {
		sink = m.logSinkFor(id)
	}

	// Explicit nil-interface for the no-caller case so drainSentryStdio's
	// nil-check actually fires (a typed-nil *os.File would slip through).
	var outSink, errSink io.WriteCloser
	if sb.stdoutToCaller != nil {
		outSink = sb.stdoutToCaller
	}
	if sb.stderrToCaller != nil {
		errSink = sb.stderrToCaller
	}
	if sb.stdoutInternalR != nil {
		go drainSentryStdio(sb.stdoutInternalR, outSink, sink.Stdout)
	}
	if sb.stderrInternalR != nil {
		go drainSentryStdio(sb.stderrInternalR, errSink, sink.Stderr)
	}

	log.Info("Starting sandbox")

	// Ingress: when a resident listener was requested, open the host AF_UNIX
	// socket that fronts it and donate it to the start subprocess so the
	// Sentry's PluginStack PreInit can wire the inbound forwarder. nil when
	// inbound is disabled, leaving the sandbox egress-only.
	var inboundFile *os.File
	if sb.inboundListenAddr != "" {
		path := InboundSockPath(m.stateDir, id)
		f, err := openInboundListener(path)
		if err != nil {
			return fmt.Errorf("opening inbound listener: %w", err)
		}
		inboundFile = f
		sb.InboundSocket = path
		// The Sentry holds its own dup after start; drop ours either way.
		defer inboundFile.Close()
	}

	if err := runscStart(ctx, m.stateDir, string(id), sb.initStr, inboundFile); err != nil {
		return err
	}

	m.mu.Lock()
	sb.Phase = SandboxRunning
	m.stdSinks[id] = sink
	m.mu.Unlock()

	// Ingress readiness gate: hold Start open until the resident server is
	// actually accepting through the inbound forwarder, so a caller that gets
	// a successful Start can route traffic immediately. Egress-only sandboxes
	// skip this entirely. On timeout the sandbox is left Running for the
	// caller to Delete — Start's contract is "ready or error".
	if sb.inboundListenAddr != "" {
		if err := waitInboundReady(ctx, sb.InboundSocket, inboundReadyTimeout); err != nil {
			return fmt.Errorf("inbound readiness: %w", err)
		}
	}

	log.Info("Sandbox started")
	return nil
}

// Wait blocks until the sandbox's init process exits and returns its exit
// code. ErrNotFound if the sandbox is unknown. The caller is responsible
// for calling Delete after Wait returns.
func (m *Manager) Wait(ctx context.Context, id SandboxID) (int, error) {
	m.mu.Lock()
	_, ok := m.sandboxes[id]
	m.mu.Unlock()
	if !ok {
		return -1, ErrNotFound
	}

	waitCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.waiters[id] = cancel
	m.mu.Unlock()

	exitCode, err := runscWait(waitCtx, m.stateDir, string(id))

	m.mu.Lock()
	sb, sbOK := m.sandboxes[id]
	if sbOK {
		sb.Phase = SandboxStopped
	}
	delete(m.waiters, id)
	cancel()
	sink, hasSink := m.stdSinks[id]
	delete(m.stdSinks, id)
	m.mu.Unlock()

	if sbOK {
		// On Wait completion the Sentry exited; child-side FDs are
		// useless. Close everything so the caller's reader on sb.Stdout /
		// sb.Stderr sees EOF promptly.
		sb.closeStdio()
	}
	if hasSink && sink.Close != nil {
		sink.Close()
	}

	if err != nil {
		return -1, err
	}
	return exitCode, nil
}

// Stop sends SIGTERM and moves the sandbox Running -> Stopping. It does
// NOT block for exit: the caller polls Status / Wait for the eventual
// transition to Stopped. Lands in Stopped synchronously only if the
// sandbox had already exited before the signal.
func (m *Manager) Stop(ctx context.Context, id SandboxID) error {
	m.mu.Lock()
	sb, ok := m.sandboxes[id]
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}

	st, err := runscState(ctx, m.stateDir, string(id))
	if err != nil {
		if isRunscNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	if st.Status == runscStatusStopped {
		m.mu.Lock()
		sb.Phase = SandboxStopped
		m.mu.Unlock()
		return nil
	}

	slog.Info("Sending SIGTERM to sandbox", "sandbox.id", string(id), "pid", st.Pid)
	if err := runscKill(ctx, m.stateDir, string(id), "SIGTERM"); err != nil {
		return err
	}

	m.mu.Lock()
	sb.Phase = SandboxStopping
	m.mu.Unlock()
	return nil
}

// Kill sends SIGKILL to the sandbox's init via runsc — the non-graceful stop.
func (m *Manager) Kill(ctx context.Context, id SandboxID) error {
	m.mu.Lock()
	_, ok := m.sandboxes[id]
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}

	if err := runscKill(ctx, m.stateDir, string(id), "SIGKILL"); err != nil {
		if isRunscNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("SIGKILL sandbox: %w", err)
	}
	return nil
}

// Delete destroys the sandbox and frees its on-host state. `runsc delete
// --force` SIGKILLs anything still running.
func (m *Manager) Delete(ctx context.Context, id SandboxID) error {
	log := slog.With(slog.String("sandbox.id", string(id)))

	m.mu.Lock()
	_, ok := m.sandboxes[id]
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}

	if err := runscDelete(ctx, m.stateDir, string(id)); err != nil && !isRunscNotExist(err) {
		log.Error("Failed to destroy sandbox via runsc", "error", err)
	}

	if err := removeSandboxCgroup(m.hostCgroupPath, id); err != nil {
		// Leftover cgroup dirs don't compromise correctness — the next
		// host incarnation rebuilds the hierarchy from scratch — but they
		// shouldn't accumulate silently either.
		log.Error("Failed to remove per-sandbox cgroup", "error", err)
	}

	m.removeSandboxNetConfig(id)
	m.removeRunscBundleDir(id)
	// The inbound socket is a sibling of the per-sandbox state dir, so the
	// runsc-side teardown above doesn't catch it — unlink it explicitly.
	// No-op for egress-only sandboxes (the file won't exist).
	removeInboundSock(m.stateDir, id)
	// removeSandboxDebugLog intentionally NOT called — keep per-sandbox
	// Sentry logs for post-mortem inspection.

	m.deregister(id)

	log.Info("Sandbox deleted")
	return nil
}

// deregister removes a sandbox's in-memory registration — the m.sandboxes
// entry, its Wait watcher, and its stdio sink — freeing the id for a future
// Create. Both Delete and Purge must release the id: a purge that tears down
// only on-disk state leaves every stop-then-recreate flow (a crashed resident,
// a per-tenant disengage/re-engage) permanently wedged on ErrAlreadyExists.
func (m *Manager) deregister(id SandboxID) {
	// Collect the waiter cancel + sink under the lock but invoke them
	// after release: cancelling a context can wake goroutines that need
	// to reacquire m.mu (e.g. the Wait goroutine itself), and holding the
	// lock across cancel() risks self-deadlock.
	m.mu.Lock()
	sb, hasSandbox := m.sandboxes[id]
	delete(m.sandboxes, id)
	cancelWaiter, hasWaiter := m.waiters[id]
	if hasWaiter {
		delete(m.waiters, id)
	}
	sink, hasSink := m.stdSinks[id]
	delete(m.stdSinks, id)
	m.mu.Unlock()

	if hasSandbox {
		sb.closeStdio()
	}
	if hasWaiter {
		cancelWaiter()
	}
	if hasSink && sink.Close != nil {
		sink.Close()
	}
}

// Status returns the current Instance for id, or [ErrNotFound]. It
// refreshes Phase from `runsc state`.
func (m *Manager) Status(ctx context.Context, id SandboxID) (*Instance, error) {
	m.mu.Lock()
	sb, ok := m.sandboxes[id]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}

	st, err := runscState(ctx, m.stateDir, string(id))
	if err != nil {
		if isRunscNotExist(err) {
			m.mu.Lock()
			sb.Phase = SandboxStopped
			m.mu.Unlock()
			return sb, nil
		}
		return nil, fmt.Errorf("getting runsc state: %w", err)
	}

	m.mu.Lock()
	sb.Phase = phaseFromRunscState(st.Status)
	m.mu.Unlock()
	return sb, nil
}

// List returns a snapshot of all live instances.
func (m *Manager) List() []*Instance {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*Instance, 0, len(m.sandboxes))
	for _, sb := range m.sandboxes {
		result = append(result, sb)
	}
	return result
}

// Cleanup reconciles on-host runsc state against the in-process instance
// table, reaping orphans left by a previous host incarnation. Scans the
// runsc --root dir directly rather than forking `runsc list`.
func (m *Manager) Cleanup(ctx context.Context) error {
	slog.Info("Cleaning up orphaned sandboxes")

	entries, err := os.ReadDir(m.stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("listing orphaned sandboxes: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		slog.Info("Found orphaned sandbox, destroying", "sandbox.id", e.Name())
		m.Purge(ctx, SandboxID(e.Name()))
	}
	return nil
}

// Purge is the best-effort, error-swallowing teardown used on cleanup
// paths where a hung Delete must not pin the caller. Safe to call before
// Create against a stale ID: runsc delete is idempotent for not-found
// containers, and the in-memory registration is released so the id is
// immediately re-creatable (crash self-heal, per-tenant stop-then-recreate).
func (m *Manager) Purge(ctx context.Context, id SandboxID) {
	log := slog.With(slog.String("sandbox.id", string(id)))

	if err := runscDelete(ctx, m.stateDir, string(id)); err != nil && !isRunscNotExist(err) {
		log.Error("Destroy of orphaned sandbox failed; falling back to RemoveAll", "error", err)
	}
	if err := os.RemoveAll(filepath.Join(m.stateDir, string(id))); err != nil {
		log.Error("RemoveAll of state dir failed", "error", err)
	}
	m.removeRunscBundleDir(id)
	removeInboundSock(m.stateDir, id)
	m.deregister(id)
}

func (m *Manager) runscBundleDir(id SandboxID) string {
	return filepath.Join(m.stateDir, string(id)+"-bundle")
}

func (m *Manager) ensureRunscBundleDir(id SandboxID) (string, error) {
	dir := m.runscBundleDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating runsc bundle dir: %w", err)
	}
	return dir, nil
}

func (m *Manager) removeRunscBundleDir(id SandboxID) {
	_ = os.RemoveAll(m.runscBundleDir(id))
}

// runsc emits these OCI status values; see runsc/container/status.go.
const (
	runscStatusCreating = "creating"
	runscStatusCreated  = "created"
	runscStatusRunning  = "running"
	runscStatusStopped  = "stopped"
)

func phaseFromRunscState(status string) SandboxPhase {
	switch status {
	case runscStatusCreating:
		return SandboxCreating
	case runscStatusCreated:
		return SandboxReady
	case runscStatusRunning:
		return SandboxRunning
	default:
		return SandboxStopped
	}
}

// isRunscNotExist reports whether err is runsc's "container not found"
// shape. runsc folds the phrase into stderr from CombinedOutput.
func isRunscNotExist(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "does not exist")
}
