package sandbox

// EgressController is the OPTIONAL egress-policy extension of a [Runtime]. The
// core Runtime is deliberately tenant- and egress-neutral; an implementation
// that also mediates egress (clrk's internal worker wrapper does, via the
// worker egress bridge) additionally satisfies EgressController so the egress
// config plane — APO-723's localhost Config/ApplyEgress gRPC — can push live
// routing/policy/attribution without the core seam growing egress concerns.
//
// This package defines the signatures only; the data-path implementation is
// ported from clrk's internal/worker/sandbox wrapper (egress_bridge, the
// sentrystack forwarders, PROXY v2 identity) by the egress track
// (APO-713/APO-722). Unlike clrk — where one sandbox hosts exactly one agent
// workload — a workerd resident hosts every compute Service of its project,
// and Services select egress gateways independently, so egress state is keyed
// per Service within the sandbox.
//
// A caller probes for egress support with a type assertion:
//
//	if ec, ok := rt.(EgressController); ok {
//		_ = ec.SetServiceEgress(id, services)
//	}
type EgressController interface {
	// SetServiceEgress installs the full set of per-Service egress planes for
	// the sandbox. Live-swappable and level-triggered: it replaces the prior
	// set atomically, so a Service absent from the set has no egress plane.
	SetServiceEgress(id SandboxID, services []ServiceEgress) error

	// SetInvocationID stamps the current invocation ID carried in PROXY v2
	// TLVs on egress connections dialed through this sandbox, for attribution.
	SetInvocationID(id SandboxID, invocationID string) error
}

// ServiceEgress is one compute Service's egress plane within the sandbox: the
// EgressGateway listeners its egress may dial and its authorization policy.
type ServiceEgress struct {
	// Service is the compute Service name this plane belongs to.
	Service string
	// Backends is the set of EgressGateway listeners the Service may dial.
	Backends []BackendListener
	// Policy is the Service's egress authorization plane; nil means allow-all
	// (no MITM, no enforcement) — the implicit built-in "default" gateway.
	Policy *Policy
}

// BackendListener describes one EgressGateway listener the sandbox can dial.
// It is the pure (CRD-free) egress.BackendListener shape from clrk; the egress
// track consumes it unchanged.
type BackendListener struct {
	// Name mirrors the EgressListener name from the CRD; used for logs and for
	// EgressRoute parentRef.sectionName matching.
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

// Policy is a per-Service egress authorization plane an [EgressController]
// installs: the EgressGateway defaultPolicy paired with the allow rules
// compiled from the EgressRoutes attached to that gateway. A destination
// matched by any rule is allowed; otherwise DefaultDeny decides (mirroring
// clrk's egress.SandboxPolicy.Allow). Nothing enforces it until the egress
// data path is wired (the forwarder installer, APO-713); a nil *Policy means
// allow-all.
type Policy struct {
	// DefaultDeny denies destinations not matched by any rule. False (with no
	// rules) is allow-all.
	DefaultDeny bool
	// Rules are the compiled per-destination allow rules. Dimensions within a
	// rule are ANDed; rules are ORed.
	Rules []Rule
}

// Rule is one compiled EgressRouteMatch: an AND of destination dimensions.
// Each present dimension must match; an absent dimension matches anything.
// The per-destination mode selection (gateway | direct) lands with APO-722.
type Rule struct {
	// DestinationCIDRs match the destination IP. Single IPs are /32 or /128.
	DestinationCIDRs []string
	// DestinationHostnames match the DNS-bound destination name; exact or
	// single-label wildcard ("*.example.com").
	DestinationHostnames []string
	// Ports match the destination port.
	Ports []PortRange
	// Protocol is the L4 protocol ("TCP"); empty matches any.
	Protocol string
	// Listeners are the BackendListener names this rule routes via, from the
	// route's parentRef.sectionName. Empty = all of the gateway's listeners.
	Listeners []string
}

// PortRange is an inclusive destination port range; single ports have
// Start == End.
type PortRange struct {
	Start int32
	End   int32
}
