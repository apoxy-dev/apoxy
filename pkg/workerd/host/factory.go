// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"fmt"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

// ResidentFactory constructs per-tenant ResidentHosts over ONE shared sandbox
// core. The core must be shared because its state dir (runsc --root), image
// store, and host cgroup are process-wide; in particular the core's cleanup
// purges the ENTIRE state dir — every tenant's resident — which is why orphan
// reaping lives here as a boot-only operation (CleanupOrphans) instead of on
// the per-tenant ResidentRuntime surface.
type ResidentFactory struct {
	core sandbox.Runtime
	base ResidentConfig

	mu      sync.Mutex
	engaged bool
}

// NewResidentFactory builds the shared sandbox core from base. Base carries the
// process-wide config (StateDir/RootDir/ImageBaseDir/WorkerdImage/ListenAddr/
// ControlForwardAddr); Tenant and ControlHostAddr are per-resident and filled
// in by NewResident.
func NewResidentFactory(base ResidentConfig) (*ResidentFactory, error) {
	if base.WorkerdImage == "" {
		return nil, fmt.Errorf("workerd-host: ResidentConfig requires WorkerdImage")
	}
	core, err := newCore(Config{StateDir: base.StateDir, RootDir: base.RootDir, ImageBaseDir: base.ImageBaseDir})
	if err != nil {
		return nil, err
	}
	return newResidentFactoryWithCore(core, base), nil
}

// newResidentFactoryWithCore injects a sandbox core directly, for fake-driven
// tests on any platform.
func newResidentFactoryWithCore(core sandbox.Runtime, base ResidentConfig) *ResidentFactory {
	return &ResidentFactory{core: core, base: base}
}

// NewResident constructs the resident host for a tenant, listening for control
// connections on controlHostAddr. It is a pure constructor: get-or-create
// semantics and lifecycle (who calls EnsureResident/Stop when) belong to the
// caller (pkg/workerd/manager.ResidentManager, which fakes this seam in tests
// — hence the interface return).
func (f *ResidentFactory) NewResident(tenant, controlHostAddr string) (ResidentRuntime, error) {
	if err := names.ValidateTenant(tenant); err != nil {
		return nil, fmt.Errorf("workerd-host: %w", err)
	}
	if controlHostAddr == "" {
		return nil, fmt.Errorf("workerd-host: resident for tenant %q requires a control host address", tenant)
	}
	cfg := f.base
	cfg.Tenant = tenant
	cfg.ControlHostAddr = controlHostAddr

	f.mu.Lock()
	f.engaged = true
	f.mu.Unlock()
	return newResidentHostWithCore(f.core, cfg), nil
}

// CleanupOrphans reaps sandboxes left behind by a previous host incarnation.
// It purges the whole shared state dir, so it must run exactly once at process
// start, before any resident exists; a call after the first NewResident is
// refused rather than trusted to be safe.
func (f *ResidentFactory) CleanupOrphans(ctx context.Context) error {
	f.mu.Lock()
	engaged := f.engaged
	f.mu.Unlock()
	if engaged {
		return fmt.Errorf("workerd-host: CleanupOrphans called after residents were created; it purges every tenant's state and is boot-only")
	}
	return f.core.Cleanup(ctx)
}
