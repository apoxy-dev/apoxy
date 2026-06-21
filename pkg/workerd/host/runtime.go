// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

// Config constructs a Runtime.
type Config struct {
	// StateDir is runsc's --root (one subdirectory per sandbox).
	StateDir string
	// RootDir is the host staging area for generated config and per-sandbox
	// netconfig.
	RootDir string
	// ImageBaseDir is where OCI bundle images are pulled and extracted.
	ImageBaseDir string
}

// ResidentRef is the desired state of one resident workerd instance.
type ResidentRef struct {
	// Tenant is the isolation slot; one live workerd per tenant.
	Tenant string
	// Revision is the ServiceRevision name — the reload key.
	Revision string
	// Bundle is the digest-pinned OCI artifact to run.
	Bundle computev1alpha1.BundleRef
	// Config is the serving config (runtime overrides, bindings, env, mode).
	Config computev1alpha1.ServiceConfigSpec
	// Socket is the listening socket workerd binds.
	Socket SocketSpec
}

// Resident tracks one live (tenant) slot.
type Resident struct {
	Tenant    string
	Revision  string
	SandboxID sandbox.SandboxID
	Socket    SocketSpec
	Phase     sandbox.SandboxPhase
	// SandboxIP is the in-Sentry container IP the workerd socket binds on.
	// There is no host route to it — reaching the worker goes through
	// InboundSocket — but it is surfaced here for per-tenant isolation
	// assertions and for the lifecycle owner (APO-796).
	SandboxIP netip.Addr

	// InboundSocket is the host AF_UNIX socket path that fronts the in-Sentry
	// worker via the APO-694 ingress forwarder. An Envoy upstream cluster
	// (APO-628) — or the acceptance test — dials this to reach the worker's
	// fetch handler. Set once the resident is Running; empty if the socket
	// is non-HTTP.
	InboundSocket string
}

// Runtime is the workerd policy layer over the tenant-neutral sandbox.Runtime.
// It owns bundle->config reconstruction, the workerd `serve` argv, the config
// mount, and per-tenant resident lifecycle with make-before-break reload.
// APO-796 (ServiceManager) drives many residents through this type; 625's own
// cmd/workerd-host drives one.
type Runtime struct {
	core    sandbox.Runtime
	rootDir string

	// fetchManifest resolves a bundle image ref to its BundleManifest (the OCI
	// config blob). A seam so tests inject a manifest without a registry.
	fetchManifest func(ctx context.Context, imageRef string) (computev1alpha1.BundleManifest, error)

	mu        sync.Mutex
	residents map[string]*Resident // keyed by Tenant
}

// NewRuntime constructs the workerd host runtime. The concrete sandbox core is
// platform-specific: linux builds the gVisor Manager; other platforms return an
// unsupported-platform error.
func NewRuntime(cfg Config) (*Runtime, error) {
	core, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		core:          core,
		rootDir:       cfg.RootDir,
		fetchManifest: FetchBundleManifest,
		residents:     make(map[string]*Resident),
	}, nil
}

// newRuntimeWithCore injects a sandbox core and manifest fetcher directly. Used
// by tests to exercise the wrapper logic against a fake on any platform.
func newRuntimeWithCore(core sandbox.Runtime, rootDir string, fetch func(context.Context, string) (computev1alpha1.BundleManifest, error)) *Runtime {
	return &Runtime{
		core:          core,
		rootDir:       rootDir,
		fetchManifest: fetch,
		residents:     make(map[string]*Resident),
	}
}

// Ensure reconciles the tenant slot to want. No resident -> pull+create+start.
// A resident on a different revision -> make-before-break reload (start the new
// one, then drain the old). Same revision -> no-op. Idempotent.
func (r *Runtime) Ensure(ctx context.Context, want ResidentRef) (*Resident, error) {
	r.mu.Lock()
	cur := r.residents[want.Tenant]
	r.mu.Unlock()

	if cur != nil && cur.Revision == want.Revision {
		return cur, nil
	}

	next, err := r.startResident(ctx, want)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.residents[want.Tenant] = next
	r.mu.Unlock()

	if cur != nil {
		// Make-before-break: the new revision is already up before we drain
		// the old one, so no fetch is dropped during the swap.
		r.drainResident(ctx, cur)
	}
	return next, nil
}

func (r *Runtime) startResident(ctx context.Context, want ResidentRef) (*Resident, error) {
	if want.Tenant == "" || want.Revision == "" {
		return nil, fmt.Errorf("workerd-host: Ensure requires Tenant and Revision")
	}
	imageRef, err := bundleImageRef(want.Bundle)
	if err != nil {
		return nil, err
	}
	manifest, err := r.fetchManifest(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("fetching bundle manifest: %w", err)
	}
	capnp, err := BuildWorkerdConfig(BuildInput{
		Manifest:  manifest,
		Config:    want.Config,
		Socket:    want.Socket,
		AssetsDir: assetsDir(manifest),
	})
	if err != nil {
		return nil, fmt.Errorf("building workerd config: %w", err)
	}

	id := sandboxID(want.Tenant, want.Revision)
	cfgHostPath, err := stageConfig(r.rootDir, id, capnp)
	if err != nil {
		return nil, fmt.Errorf("staging workerd config: %w", err)
	}

	spec := buildSpec(id, imageRef, want, cfgHostPath)
	inst, err := r.core.Create(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("creating sandbox: %w", err)
	}
	if err := r.core.Start(ctx, id); err != nil {
		r.core.Purge(ctx, id)
		return nil, fmt.Errorf("starting sandbox: %w", err)
	}
	return &Resident{
		Tenant:    want.Tenant,
		Revision:  want.Revision,
		SandboxID: id,
		Socket:    want.Socket,
		Phase:     sandbox.SandboxRunning,
		SandboxIP: inst.SandboxIP,
		// Populated by the core during Start (inst is the same instance the
		// manager mutated), so it reflects the opened ingress socket here.
		InboundSocket: inst.InboundSocket,
	}, nil
}

// drainResident gracefully stops and tears down a superseded resident.
func (r *Runtime) drainResident(ctx context.Context, res *Resident) {
	_ = r.core.Stop(ctx, res.SandboxID)
	// Stop is non-blocking; for the standalone runtime we tear down
	// best-effort so on-host state doesn't accumulate. A full lifecycle owner
	// (APO-796) polls Status to Stopped before Delete.
	r.core.Purge(ctx, res.SandboxID)
}

// Stop gracefully drains the tenant's resident and forgets the slot.
func (r *Runtime) Stop(ctx context.Context, tenant string) error {
	r.mu.Lock()
	res := r.residents[tenant]
	delete(r.residents, tenant)
	r.mu.Unlock()
	if res == nil {
		return nil
	}
	if err := r.core.Stop(ctx, res.SandboxID); err != nil && err != sandbox.ErrNotFound {
		return err
	}
	r.core.Purge(ctx, res.SandboxID)
	return nil
}

// List returns a snapshot of the live residents.
func (r *Runtime) List() []*Resident {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Resident, 0, len(r.residents))
	for _, res := range r.residents {
		out = append(out, res)
	}
	return out
}

// Cleanup reaps orphan sandboxes left by a previous host incarnation.
func (r *Runtime) Cleanup(ctx context.Context) error {
	return r.core.Cleanup(ctx)
}
