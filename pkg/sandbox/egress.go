package sandbox

// EgressController is the OPTIONAL egress-policy extension of a [Runtime]. The
// core Runtime is deliberately tenant- and egress-neutral; an implementation
// that also mediates egress (clrk's internal worker wrapper does, via the
// worker egress bridge) additionally satisfies EgressController so the egress
// config plane — APO-723's localhost Config/ApplyEgress gRPC — can push live
// routing/policy/attribution without the core seam growing egress concerns.
//
// This package defines the signatures only; the implementation lives in clrk's
// internal/worker/sandbox wrapper, which retains the egress data path
// (egress_bridge, the sentrystack forwarders, PROXY v2 identity). The egress
// track (APO-722/723/726) is what wires an external consumer to it. Until then
// [Policy] is a forward declaration the egress track fleshes out.
//
// A caller probes for egress support with a type assertion:
//
//	if ec, ok := rt.(EgressController); ok {
//		_ = ec.SetEgressBackends(id, backends)
//	}
type EgressController interface {
	// SetEgressBackends installs the set of EgressGateway listeners the
	// sandbox may dial. Live-swappable: replaces the prior set.
	SetEgressBackends(id SandboxID, backends []BackendListener) error

	// SetEgressPolicy installs the per-sandbox egress authorization plane.
	// Live-swappable; a nil policy means allow-all (no MITM, no enforcement).
	SetEgressPolicy(id SandboxID, policy *Policy) error

	// SetInvocationID stamps the current invocation ID carried in PROXY v2
	// TLVs on egress connections dialed through this sandbox, for attribution.
	SetInvocationID(id SandboxID, invocationID string) error
}

// BackendListener describes one EgressGateway listener the sandbox can dial.
// It is the pure (CRD-free) egress.BackendListener shape from clrk; the egress
// track consumes it unchanged.
type BackendListener struct {
	// Name mirrors the EgressListener name from the CRD; used for logs and for
	// EgressL4Route parentRef.sectionName matching.
	Name string
	// Addr is the host:port the sandbox dials. Empty means "listener exists
	// but its data plane isn't ready yet" — the dialer skips it.
	Addr string
	// Shape is the on-the-wire protocol selector ("tls-terminate",
	// "tls-passthrough", "tcp", "http", "https"). Diagnostic surface; the
	// dialer tie-breaks on Priority, not Shape.
	Shape string
	// MatchPort, when non-zero, narrows this listener to the sandbox's
	// destination port. Zero = catch-all for this shape.
	MatchPort int32
	// Priority is the precomputed shape rank used as a tiebreaker when
	// multiple listeners match the same dst port. Higher wins.
	Priority int
}

// Policy is the per-sandbox egress authorization plane an [EgressController]
// installs. APO-723 gives it the default decision only — enough for the
// config plane to carry and record; the per-destination route rules (the
// gateway | direct mode table, mirroring clrk's egress.SandboxPolicy) land
// with APO-722, and nothing enforces it until the egress data path is wired
// (the forwarder installer, APO-713). The core [Runtime] never reads it; a
// nil *Policy means allow-all.
type Policy struct {
	// DefaultDeny denies destinations not matched by any route rule. False
	// (with no rules) is allow-all.
	DefaultDeny bool
}
