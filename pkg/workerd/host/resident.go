// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

// The resident model (APO-796): ONE long-lived workerd per TENANT (project)
// runs the static dispatcher worker (BuildResidentConfig) and hosts that
// tenant's service/revisions as WorkerLoader isolates. Single-project
// topologies (apoxy dev, dedicated mode) run exactly one resident with the
// empty tenant; the shared backplane's manager runs one per engaged project.
// This is distinct from the per-(tenant, revision) Runtime above, which 625's
// cmd/workerd-host drives — that bakes one customer worker per sandbox; this
// bakes the dispatcher and loads customers at runtime over the control channel.

const (
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
	// Tenant is the project UUID this resident serves; empty for the
	// single-project topologies (apoxy dev, dedicated mode). It keys the
	// sandbox id and the inbound socket path via pkg/workerd/names, so the
	// gateway's per-project resident cluster dials the matching socket.
	Tenant string

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
//
// The interface deliberately has NO Cleanup: the underlying sandbox core's
// cleanup purges the entire runsc state dir — every tenant's resident — so it
// is a process-wide, boot-only operation owned by ResidentFactory
// (CleanupOrphans), not something a per-tenant driver can be handed.
type ResidentRuntime interface {
	// EnsureResident brings this tenant's resident up if it is not already, and
	// is idempotent: a second call while the resident is up returns the same
	// instance without recreating the sandbox.
	EnsureResident(ctx context.Context) (*ResidentInstance, error)
	// Stop drains and tears down the resident, including its staged config.
	Stop(ctx context.Context) error
}

var _ ResidentRuntime = (*ResidentHost)(nil)

// ResidentHost owns one tenant's resident workerd. It stages the static
// dispatcher config, runs it in a single sandbox with the inbound forwarder and
// the manager control socket, and exposes idempotent lifecycle for the resident
// reconciler. Construct via ResidentFactory.NewResident so all residents share
// one sandbox core.
type ResidentHost struct {
	core    sandbox.Runtime
	cfg     ResidentConfig
	id      sandbox.SandboxID
	rootDir string

	mu   sync.Mutex
	inst *ResidentInstance
	// staged records that THIS host staged config on disk and has not yet
	// removed it. It gates Stop's staging-dir removal: the path is
	// deterministic per tenant, so an unconditional RemoveAll from a stale
	// duplicate Stop (two repair paths racing on the same dead entry) would
	// delete a successor resident's freshly staged config.
	staged bool

	// bridge is this resident's host egress data-path endpoint (APO-713): the
	// loopback TCP listener the in-Sentry forwarder tunnels every outbound flow
	// to. Its addr is sealed into the sandbox spec as EgressHostAddr, so it must
	// be up before the resident starts. nil when the sandbox core isn't
	// egress-capable (fake-driven tests) or before the first boot. Mutated only
	// under h.mu.
	bridge *egressBridge
}

// newResidentHostWithCore injects a sandbox core directly, for the factory and
// for fake-driven tests on any platform.
func newResidentHostWithCore(core sandbox.Runtime, cfg ResidentConfig) *ResidentHost {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultResidentListenAddr
	}
	if cfg.ControlForwardAddr == "" {
		cfg.ControlForwardAddr = defaultControlForwardAddr
	}
	return &ResidentHost{core: core, cfg: cfg, id: names.ResidentID(cfg.Tenant), rootDir: cfg.RootDir}
}

// EnsureResident implements ResidentRuntime.
func (h *ResidentHost) EnsureResident(ctx context.Context) (*ResidentInstance, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// carryEgress preserves the applied egress SERVICES across a self-heal
	// recreation. A recreated sandbox re-registers empty (deny-all) egress state,
	// and the config pusher only re-pushes on API events — so without this a
	// crashed resident comes back with ALL egress denied until an unrelated
	// egress-relevant event or the controller cache resync (potentially hours).
	// The recreated sandbox is the same logical resident (same id, same project,
	// same desired config), so re-applying its last services is correct. The
	// generation is NOT carried: it resets to 0 with the fresh sandbox so a
	// subsequent push — even a LOWER generation from a restarted reconciler —
	// still re-syncs authoritatively (see TestResidentHost_ApplyEgress).
	var carryEgress *EgressState
	if h.inst != nil {
		// Don't trust the cached record blindly: the resident workerd can die out
		// from under us (OOM, crash, host reap). Probe the sandbox so the
		// reconciler's per-reconcile EnsureResident actually self-heals instead of
		// re-handing-out a dead instance forever.
		st, err := h.core.Status(ctx, h.id)
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
			slog.Warn("Resident workerd no longer running; recreating",
				"sandbox.id", string(h.id), "phase", phase)
			// Snapshot the applied egress BEFORE Purge drops it, so its services
			// can be re-applied to the recreated sandbox below. Only worth carrying
			// when there were service planes — an empty state recreates to the same
			// deny-all anyway.
			if ec, ok := h.core.(*egressCore); ok {
				if saved, had := ec.LookupEgressState(h.id); had && len(saved.Services) > 0 {
					s := saved
					carryEgress = &s
				}
			}
			h.core.Purge(ctx, h.id)
			h.inst = nil
			// The stale bridge's addr belonged to the dead sandbox's spec; drop
			// it so startEgress binds a fresh one for the recreated sandbox.
			h.closeBridge()
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
	cfgHostPath, err := stageConfig(h.rootDir, h.id, capnp)
	if err != nil {
		return nil, fmt.Errorf("staging resident config: %w", err)
	}
	h.staged = true

	// The egress bridge must be listening before the resident starts so the
	// in-Sentry forwarder's first outbound dial lands. Its addr is sealed into
	// the spec below as EgressHostAddr.
	egressInit, err := h.startEgress()
	if err != nil {
		return nil, err
	}

	spec := buildResidentSpec(h.id, h.cfg, cfgHostPath, egressInit)
	inst, err := h.core.Create(ctx, spec)
	if err != nil {
		h.closeBridge()
		return nil, fmt.Errorf("creating resident sandbox: %w", err)
	}
	// Re-apply the preserved egress services before the worker starts, so a
	// self-healed resident is immediately back to its last-pushed policy instead
	// of serving under a fresh deny-all until the next config push. Generation is
	// reset to 0 (the fresh sandbox's baseline) so the reconciler's next push —
	// whatever its generation — still re-syncs authoritatively.
	if carryEgress != nil {
		if ec, ok := h.core.(*egressCore); ok {
			if _, err := ec.applyEgress(h.id, EgressApply{
				Services:     carryEgress.Services,
				InvocationID: carryEgress.InvocationID,
				Generation:   0,
			}); err != nil {
				slog.Warn("Failed to re-apply egress after resident recreation",
					"sandbox.id", string(h.id), "error", err)
			} else {
				slog.Info("Re-applied egress services after resident recreation",
					"sandbox.id", string(h.id), "services", len(carryEgress.Services))
			}
		}
	}
	if err := h.core.Start(ctx, h.id); err != nil {
		h.core.Purge(ctx, h.id)
		h.closeBridge()
		return nil, fmt.Errorf("starting resident sandbox: %w", err)
	}
	h.inst = &ResidentInstance{
		SandboxID:     h.id,
		InboundSocket: inst.InboundSocket,
		SandboxIP:     inst.SandboxIP,
	}
	return h.inst, nil
}

// Stop implements ResidentRuntime.
func (h *ResidentHost) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inst != nil {
		if err := h.core.Stop(ctx, h.id); err != nil && err != sandbox.ErrNotFound {
			return err
		}
		h.core.Purge(ctx, h.id)
		h.inst = nil
	}
	// Tear down the egress bridge with the resident so a disengaged tenant
	// doesn't leak its loopback listener.
	h.closeBridge()
	// Remove the staged dispatcher config too: with per-tenant residents a
	// stopped tenant would otherwise leak its rootDir/<id> staging dir on every
	// disengage. Only when THIS host staged it — the path is shared with any
	// successor resident for the same tenant.
	if h.staged && h.rootDir != "" {
		if err := os.RemoveAll(stagingDir(h.rootDir, h.id)); err != nil {
			slog.Warn("Failed to remove staged resident config",
				"sandbox.id", string(h.id), "error", err)
		} else {
			h.staged = false
		}
	}
	return nil
}

// startEgress brings up this resident's host egress bridge and returns the
// EgressInit to seal into the sandbox spec. It reads the egress core's recorded
// per-resident state (the same *egressCore ApplyEgress writes to), so the
// bridge and the config plane share one state. When the core isn't
// egress-capable (fake-driven tests), egress stays disabled — an empty
// EgressInit means the in-Sentry forwarder installs nothing, so outbound is
// fail-closed. Caller holds h.mu.
func (h *ResidentHost) startEgress() (sandbox.EgressInit, error) {
	ec, ok := h.core.(*egressCore)
	if !ok {
		return sandbox.EgressInit{}, nil
	}
	// A prior boot's bridge (if any) is stale — its addr belonged to the old
	// sandbox spec — so bind a fresh one for this sandbox.
	h.closeBridge()
	br, err := startEgressBridge(h.id, ec.LookupEgressState)
	if err != nil {
		return sandbox.EgressInit{}, fmt.Errorf("starting egress bridge: %w", err)
	}
	h.bridge = br
	return sandbox.EgressInit{EgressHostAddr: br.addr()}, nil
}

// closeBridge tears down the resident's egress bridge if one is running.
// Caller holds h.mu.
func (h *ResidentHost) closeBridge() {
	if h.bridge != nil {
		if err := h.bridge.close(); err != nil {
			slog.Warn("Failed to close egress bridge", "sandbox.id", string(h.id), "error", err)
		}
		h.bridge = nil
	}
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
func buildResidentSpec(id sandbox.SandboxID, cfg ResidentConfig, cfgHostPath string, egress sandbox.EgressInit) sandbox.Spec {
	return sandbox.Spec{
		ID:    id,
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
		Egress: egress,
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
