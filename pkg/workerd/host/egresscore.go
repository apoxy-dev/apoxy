// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

// EgressState is the recorded egress configuration of one sandbox — what the
// config plane (APO-723) has applied, held for the egress data path (the
// forwarder installer / worker egress bridge, APO-713/APO-722) to consume.
// It mirrors clrk's worker sandbox EgressState.
type EgressState struct {
	// Backends is the set of EgressGateway listeners the sandbox may dial.
	Backends []sandbox.BackendListener
	// Policy is the egress authorization plane; nil means allow-all.
	Policy *sandbox.Policy
	// InvocationID is stamped on egress connections for attribution.
	InvocationID string
	// Generation is the config generation this state was applied at. It lives
	// here — not beside the caller — so the guard shares the state's exact
	// lifecycle: a recreated sandbox starts from a fresh zero-generation state
	// and can never report a generation whose config was dropped with the old
	// sandbox.
	Generation uint64
}

// egressCore wraps the tenant-neutral sandbox core with the recording
// EgressController the egress config plane pushes into. The core seam stays
// egress-neutral by design (see pkg/sandbox/egress.go); this wrapper owns the
// per-sandbox egress state exactly as clrk's internal worker wrapper does,
// keyed to sandbox lifecycle: state is settable only for a live sandbox
// (created here, not yet purged) and dropped on teardown so a reloaded
// revision's fresh sandbox never inherits a predecessor's config.
type egressCore struct {
	sandbox.Runtime

	mu     sync.RWMutex
	states map[sandbox.SandboxID]*EgressState
}

var _ sandbox.EgressController = (*egressCore)(nil)

// newEgressCore wraps core with the recording egress controller.
func newEgressCore(core sandbox.Runtime) *egressCore {
	return &egressCore{
		Runtime: core,
		states:  make(map[sandbox.SandboxID]*EgressState),
	}
}

// Create registers a fresh empty egress state once the core create succeeds.
// Registration strictly follows creation so a FAILED create can never disturb
// existing state — in particular an ErrAlreadyExists loser (a duplicate
// create racing a live sandbox) must not touch the live sandbox's applied
// config. A config push arriving before creation completes fails ErrNotFound
// and is retried by the reconciler.
func (c *egressCore) Create(ctx context.Context, spec sandbox.Spec) (*sandbox.Instance, error) {
	inst, err := c.Runtime.Create(ctx, spec)
	if err != nil {
		return nil, err
	}
	// Unconditional overwrite: a successful create means no live sandbox held
	// this id, so any existing entry is a stale leftover.
	c.mu.Lock()
	c.states[spec.ID] = &EgressState{}
	c.mu.Unlock()
	return inst, nil
}

// Delete drops the sandbox's egress state along with the sandbox.
func (c *egressCore) Delete(ctx context.Context, id sandbox.SandboxID) error {
	err := c.Runtime.Delete(ctx, id)
	if err == nil {
		c.dropState(id)
	}
	return err
}

// Purge drops the sandbox's egress state along with the sandbox. Purge is
// best-effort by contract, so the state goes unconditionally.
func (c *egressCore) Purge(ctx context.Context, id sandbox.SandboxID) {
	c.Runtime.Purge(ctx, id)
	c.dropState(id)
}

func (c *egressCore) dropState(id sandbox.SandboxID) {
	c.mu.Lock()
	delete(c.states, id)
	c.mu.Unlock()
}

// stateLocked returns the live sandbox's state record, or ErrNotFound if the
// sandbox was never created (or already torn down). Callers hold c.mu.
func (c *egressCore) stateLocked(id sandbox.SandboxID) (*EgressState, error) {
	st, ok := c.states[id]
	if !ok {
		return nil, sandbox.ErrNotFound
	}
	return st, nil
}

// SetEgressBackends replaces the sandbox's dialable EgressGateway listener
// set. Live-swappable, last-writer-wins.
func (c *egressCore) SetEgressBackends(id sandbox.SandboxID, backends []sandbox.BackendListener) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.stateLocked(id)
	if err != nil {
		return err
	}
	st.Backends = backends
	return nil
}

// SetEgressPolicy replaces the sandbox's egress authorization plane. A nil
// policy means allow-all.
func (c *egressCore) SetEgressPolicy(id sandbox.SandboxID, policy *sandbox.Policy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.stateLocked(id)
	if err != nil {
		return err
	}
	st.Policy = policy
	return nil
}

// SetInvocationID stamps the invocation id carried on egress connections
// dialed through this sandbox.
func (c *egressCore) SetInvocationID(id sandbox.SandboxID, invocationID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.stateLocked(id)
	if err != nil {
		return err
	}
	st.InvocationID = invocationID
	return nil
}

// applyEgress atomically installs one whole config push for a live sandbox
// under a single lock acquisition, so a reader can never observe one push's
// backends paired with another's policy. Idempotent and last-writer-wins:
// a push older than the applied generation is ignored and the retained
// generation is returned; equal or newer pushes replace the whole state.
// Returns ErrNotFound if the sandbox was never created or is already gone.
func (c *egressCore) applyEgress(id sandbox.SandboxID, apply EgressApply) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.stateLocked(id)
	if err != nil {
		return 0, err
	}
	if apply.Generation < st.Generation {
		return st.Generation, nil
	}
	// Clone the backends so the stored state never aliases caller memory:
	// LookupEgressState hands out shallow snapshots, and a consumer sorting
	// its snapshot in place must not race the recorded state.
	st.Backends = append([]sandbox.BackendListener(nil), apply.Backends...)
	st.Policy = apply.Policy
	st.InvocationID = apply.InvocationID
	st.Generation = apply.Generation
	return apply.Generation, nil
}

// LookupEgressState returns a snapshot of the sandbox's recorded egress
// config. This is the read seam the egress data path (APO-713's forwarder /
// bridge port) consumes per connection, mirroring clrk's LookupEgressState.
// The snapshot's Backends slice aliases the stored one and must be treated
// as read-only; applies never mutate it in place (applyEgress swaps in a
// fresh clone), so a held snapshot stays internally consistent.
func (c *egressCore) LookupEgressState(id sandbox.SandboxID) (EgressState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	st, ok := c.states[id]
	if !ok {
		return EgressState{}, false
	}
	return *st, true
}
