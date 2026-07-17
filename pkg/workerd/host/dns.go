// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"fmt"

	"github.com/apoxy-dev/apoxy/pkg/net/dns/vpcdns"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

// DNSApply is one VPC name-plane push for a sandbox — the Go shape of the
// DNSConfig/ApplyDNS request (api/workerd/v1) the manager's infra watch
// sends.
type DNSApply struct {
	// Zones are the DNS zones the resident's resolver answers authoritatively
	// for (NXDOMAIN for unbound names within them).
	Zones []string
	// Bindings is the full desired binding set; it replaces the prior set
	// atomically. Their Reachable prefixes also feed the egress bridge's SSRF
	// carve-out.
	Bindings []vpcdns.Binding
	// Generation orders applies; a push older than the last applied one for
	// the sandbox is ignored. Independent of the egress plane's generation.
	Generation uint64
}

// DNSApplier is the optional name-plane extension of [ResidentRuntime],
// mirroring [EgressApplier]: the manager's per-tenant DNSConfig gRPC sink
// probes for it with a type assertion.
type DNSApplier interface {
	// ApplyDNS installs the resident sandbox's VPC name plane atomically.
	// Idempotent, last-writer-wins by Generation; returns the generation now
	// in effect.
	ApplyDNS(apply DNSApply) (uint64, error)
}

var _ DNSApplier = (*ResidentHost)(nil)

// ApplyDNS implements [DNSApplier] for the resident, delegating to the
// egress core's atomic whole-state apply. Like the egress plane, the applied
// generation lives inside the recorded state and dies with the sandbox;
// EnsureResident carries the last-known bindings across a self-heal
// recreation at generation 0 so name resolution doesn't fall back to
// upstream-only until the next push.
func (h *ResidentHost) ApplyDNS(apply DNSApply) (uint64, error) {
	ec, ok := h.core.(*egressCore)
	if !ok {
		return 0, fmt.Errorf("workerd-host: sandbox core does not support DNS control")
	}

	h.mu.Lock()
	running := h.inst != nil
	h.mu.Unlock()
	if !running {
		return 0, fmt.Errorf("workerd-host: resident is not running: %w", sandbox.ErrNotFound)
	}
	// The resident can be torn down between the check above and the apply;
	// applyDNS then fails ErrNotFound on the dropped state, which the gRPC
	// layer maps to a retryable Unavailable.
	return ec.applyDNS(h.id, apply)
}
