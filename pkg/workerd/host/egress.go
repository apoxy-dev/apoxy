// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"fmt"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

// EgressApply is one compiled egress config push for a sandbox — the Go shape
// of the EgressConfig/ApplyEgress request (api/workerd/v1) the backplane's
// egress reconciler sends.
type EgressApply struct {
	// Services is the full desired set of per-Service egress planes for the
	// resident; it replaces the prior set atomically.
	Services []sandbox.ServiceEgress
	// InvocationID is stamped on egress connections for attribution.
	InvocationID string
	// Generation orders applies; a push older than the last applied one for
	// the sandbox is ignored.
	Generation uint64
}

// EgressApplier is the optional egress-config extension of [ResidentRuntime]:
// the manager's per-tenant EgressConfig gRPC sink (APO-723) probes for it with
// a type assertion, mirroring how callers probe the sandbox core for
// [sandbox.EgressController]. It is not part of ResidentRuntime so existing
// fakes and non-egress drivers keep compiling.
type EgressApplier interface {
	// ApplyEgress installs the resident sandbox's egress config atomically.
	// Idempotent, last-writer-wins by Generation; returns the generation now
	// in effect (the request's if applied, the newer retained one if the
	// request was stale).
	ApplyEgress(apply EgressApply) (uint64, error)
}

var _ EgressApplier = (*ResidentHost)(nil)

// ApplyEgress implements [EgressApplier] for the resident: it delegates to
// the egress core's atomic whole-state apply for this tenant's resident
// sandbox. The applied generation lives inside the recorded state, so it is
// dropped with the sandbox: a self-healed (recreated) resident starts from a
// fresh zero-generation state and the reconciler's next push — whatever its
// generation — lands the config again. To avoid a deny-all gap in that window,
// EnsureResident re-applies the last-known service planes at generation 0 across
// a recreation (the reset generation preserves the re-land property above). This
// is the worker-side sink of the egress config plane (APO-723), consumed by the
// egress data path (APO-713/APO-722).
func (h *ResidentHost) ApplyEgress(apply EgressApply) (uint64, error) {
	ec, ok := h.core.(*egressCore)
	if !ok {
		return 0, fmt.Errorf("workerd-host: sandbox core does not support egress control")
	}

	h.mu.Lock()
	running := h.inst != nil
	h.mu.Unlock()
	if !running {
		return 0, fmt.Errorf("workerd-host: resident is not running: %w", sandbox.ErrNotFound)
	}
	// The resident can be torn down between the check above and the apply;
	// applyEgress then fails ErrNotFound on the dropped state, which the
	// gRPC layer maps to a retryable Unavailable.
	return ec.applyEgress(h.id, apply)
}
