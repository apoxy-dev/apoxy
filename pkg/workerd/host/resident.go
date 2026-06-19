// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/apoxy-dev/clrk/pkg/sandbox"
)

// The resident model (APO-796): ONE long-lived workerd per backplane runs the
// static dispatcher worker (BuildResidentConfig) and hosts every service/
// revision as a WorkerLoader isolate. This is distinct from the per-(tenant,
// revision) Runtime above, which 625's cmd/workerd-host drives — that bakes one
// customer worker per sandbox; this bakes the dispatcher and loads customers at
// runtime over the control channel.

const (
	// residentSandboxID is the stable id of the single resident sandbox. There
	// is exactly one per backplane, so the id is a constant (not keyed by
	// tenant/revision like the per-revision Runtime).
	residentSandboxID sandbox.SandboxID = "apoxy-workerd-resident"
	// defaultResidentListenAddr is the dispatcher's in-sandbox http socket bind
	// address when ResidentConfig.ListenAddr is unset. The inbound forwarder
	// (APO-694) fronts it with a host AF_UNIX socket Envoy dials.
	defaultResidentListenAddr = "*:8080"
	// defaultControlForwardAddr is the in-sandbox TCP address the dispatcher's
	// MANAGER external service dials to reach the host manager. It is an
	// otherwise-unused loopback target the clrk control forwarder intercepts and
	// splices to the host manager's control listener (ControlHostAddr).
	//
	// The control path is plain TCP end to end, NOT a unix socket: clrk's
	// in-Sentry netstack has no AF_UNIX provider, AND the Sentry's own plugin
	// seccomp filter only allows socket() for AF_INET/AF_INET6 — so neither the
	// guest nor the Sentry's host-side dial can touch a host unix socket. The
	// control forwarder (the one net-new clrk dependency; see
	// docs/workerd-runtime-mvp.md) mirrors the APO-694 inbound forwarder in
	// reverse — guest TCP in, host net.Dial("tcp", ControlHostAddr) out — and
	// needs no fd donation because the Sentry shares the host net namespace.
	defaultControlForwardAddr = "127.0.0.2:80"
)

// ResidentConfig constructs a ResidentHost.
type ResidentConfig struct {
	// StateDir is runsc's --root.
	StateDir string
	// RootDir is the host staging area for the generated dispatcher config.
	RootDir string
	// ImageBaseDir is where the stock workerd image is pulled and extracted.
	ImageBaseDir string

	// WorkerdImage is the stock upstream workerd OCI image the resident runs.
	// The dispatcher source is inlined into the config, so this image carries no
	// customer code — only the workerd binary.
	WorkerdImage string
	// ListenAddr is the dispatcher's http socket bind address (workerd syntax,
	// e.g. "*:8080"). Defaults to defaultResidentListenAddr.
	ListenAddr string
	// ControlHostAddr is the HOST loopback TCP address (e.g. "127.0.0.1:2024")
	// the manager's control HTTP server listens on. The clrk control forwarder
	// dials it for each connection the dispatcher opens to ControlForwardAddr.
	ControlHostAddr string
	// ControlForwardAddr is the in-sandbox TCP address the dispatcher dials for
	// the control channel; the clrk control forwarder routes it to
	// ControlHostAddr. Defaults to defaultControlForwardAddr.
	ControlForwardAddr string
}

// ResidentInstance is the running resident, surfaced to the lifecycle owner.
type ResidentInstance struct {
	SandboxID sandbox.SandboxID
	// InboundSocket is the host AF_UNIX path that fronts the dispatcher's http
	// socket via the inbound forwarder; the backplane's resident Envoy cluster
	// dials it. Empty until Running.
	InboundSocket string
	// SandboxIP is the in-Sentry container IP (diagnostics / isolation asserts).
	SandboxIP netip.Addr
}

// ResidentRuntime is the surface the ServiceManager resident reconciler drives.
// ResidentHost implements it over the gVisor core; tests fake it on any platform.
type ResidentRuntime interface {
	// EnsureResident brings the single resident up if it is not already, and is
	// idempotent: a second call while the resident is up returns the same
	// instance without recreating the sandbox.
	EnsureResident(ctx context.Context) (*ResidentInstance, error)
	// Stop drains and tears down the resident.
	Stop(ctx context.Context) error
	// Cleanup reaps orphan sandboxes from a previous host incarnation.
	Cleanup(ctx context.Context) error
}

var _ ResidentRuntime = (*ResidentHost)(nil)

// ResidentHost owns the one resident workerd. It stages the static dispatcher
// config, runs it in a single sandbox with the inbound forwarder and the manager
// control socket, and exposes idempotent lifecycle for the resident reconciler.
type ResidentHost struct {
	core    sandbox.Runtime
	cfg     ResidentConfig
	rootDir string

	mu   sync.Mutex
	inst *ResidentInstance
}

// NewResidentHost constructs the resident host over the platform sandbox core.
func NewResidentHost(cfg ResidentConfig) (*ResidentHost, error) {
	if cfg.WorkerdImage == "" {
		return nil, fmt.Errorf("workerd-host: ResidentConfig requires WorkerdImage")
	}
	if cfg.ControlHostAddr == "" {
		return nil, fmt.Errorf("workerd-host: ResidentConfig requires ControlHostAddr")
	}
	core, err := newCore(Config{StateDir: cfg.StateDir, RootDir: cfg.RootDir, ImageBaseDir: cfg.ImageBaseDir})
	if err != nil {
		return nil, err
	}
	return newResidentHostWithCore(core, cfg), nil
}

// newResidentHostWithCore injects a sandbox core directly, for fake-driven tests
// on any platform.
func newResidentHostWithCore(core sandbox.Runtime, cfg ResidentConfig) *ResidentHost {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultResidentListenAddr
	}
	if cfg.ControlForwardAddr == "" {
		cfg.ControlForwardAddr = defaultControlForwardAddr
	}
	return &ResidentHost{core: core, cfg: cfg, rootDir: cfg.RootDir}
}

// EnsureResident implements ResidentRuntime.
func (h *ResidentHost) EnsureResident(ctx context.Context) (*ResidentInstance, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inst != nil {
		// Don't trust the cached record blindly: the resident workerd can die out
		// from under us (OOM, crash, host reap). Probe the sandbox so the
		// reconciler's per-reconcile EnsureResident actually self-heals instead of
		// re-handing-out a dead instance forever.
		st, err := h.core.Status(ctx, residentSandboxID)
		switch {
		case err == nil && st.Phase == sandbox.SandboxRunning:
			return h.inst, nil
		case errors.Is(err, sandbox.ErrNotFound) || (err == nil && st.Phase != sandbox.SandboxRunning):
			// Positively gone or no longer running: drop the stale record and
			// recreate below.
			phase := sandbox.SandboxPhase("missing")
			if st != nil {
				phase = st.Phase
			}
			slog.Warn("Resident workerd no longer running; recreating", "phase", phase)
			h.core.Purge(ctx, residentSandboxID)
			h.inst = nil
		default:
			// Transient Status error: assume the resident is still up and let the
			// next reconcile re-check, rather than churning the sandbox on a blip.
			return h.inst, nil
		}
	}

	capnp, err := BuildResidentConfig(ResidentConfigInput{
		SocketAddr:  h.cfg.ListenAddr,
		ManagerAddr: h.cfg.ControlForwardAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("building resident config: %w", err)
	}
	cfgHostPath, err := stageConfig(h.rootDir, residentSandboxID, capnp)
	if err != nil {
		return nil, fmt.Errorf("staging resident config: %w", err)
	}

	spec := buildResidentSpec(h.cfg, cfgHostPath)
	inst, err := h.core.Create(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("creating resident sandbox: %w", err)
	}
	if err := h.core.Start(ctx, residentSandboxID); err != nil {
		h.core.Purge(ctx, residentSandboxID)
		return nil, fmt.Errorf("starting resident sandbox: %w", err)
	}
	h.inst = &ResidentInstance{
		SandboxID:     residentSandboxID,
		InboundSocket: inst.InboundSocket,
		SandboxIP:     inst.SandboxIP,
	}
	return h.inst, nil
}

// Stop implements ResidentRuntime.
func (h *ResidentHost) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inst == nil {
		return nil
	}
	if err := h.core.Stop(ctx, residentSandboxID); err != nil && err != sandbox.ErrNotFound {
		return err
	}
	h.core.Purge(ctx, residentSandboxID)
	h.inst = nil
	return nil
}

// Cleanup implements ResidentRuntime.
func (h *ResidentHost) Cleanup(ctx context.Context) error {
	return h.core.Cleanup(ctx)
}

// buildResidentSpec maps the resident config to the sandbox.Spec that runs the
// stock-workerd dispatcher.
//
// The control channel (dispatcher -> host manager) is wired via the clrk control
// forwarder: cfg.ControlForwardAddr is the in-sandbox ip:port the dispatcher's
// MANAGER binding dials, and cfg.ControlHostAddr is the host loopback TCP addr the
// forwarder splices each such connection to (the manager's control server).
// These mirror InboundListenAddr/InboundSocket but in the guest->host direction
// and need no fd donation — the Sentry shares the host net namespace and
// net.Dial("tcp", ...)s the manager's control listener directly. See
// docs/workerd-runtime-mvp.md §"control channel".
func buildResidentSpec(cfg ResidentConfig, cfgHostPath string) sandbox.Spec {
	return sandbox.Spec{
		ID:    residentSandboxID,
		Image: cfg.WorkerdImage,
		// Stock workerd serving the dispatcher config. Absolute path: the sandbox
		// process env carries no PATH (the image store doesn't propagate the image's
		// Env), so a bare "workerd" won't resolve. --experimental enables the
		// workerLoader binding. (--platform=systrap is a runsc flag, already set on
		// the sandbox; workerd has no such option and exits if given it.)
		Command: []string{"/usr/bin/workerd", "serve", inJailConfigPath(), "--experimental"},
		Mounts: []sandbox.Mount{
			// The dispatcher config (read-only; rootfs is digest-shared).
			{Source: cfgHostPath, Destination: inJailConfigPath(), Type: "bind", Options: []string{"ro"}},
		},
		Stdio:  false,
		Egress: sandbox.EgressInit{},
		// Ingress (APO-694): the dispatcher's http socket has no host route, so
		// opt into the inbound forwarder; the core surfaces a host AF_UNIX socket
		// (Instance.InboundSocket) the backplane resident cluster dials.
		InboundListenAddr: hostInboundAddr(SocketSpec{Kind: HTTPSocket, Addr: cfg.ListenAddr}),
		// Control (dispatcher -> host manager): the clrk control forwarder accepts
		// the dispatcher's connections to ControlForwardAddr on an in-stack
		// listener and splices each to ControlHostAddr (the manager's control
		// server, a host loopback TCP listener). Guest->host mirror of inbound;
		// no fd donation.
		ControlForwardAddr: cfg.ControlForwardAddr,
		ControlHostAddr:    cfg.ControlHostAddr,
	}
}
