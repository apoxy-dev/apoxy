package agent

import (
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

// routeTable is the slice of router.Router the reconciler needs. Narrowing it
// keeps the reconciler testable without standing up a datapath.
type routeTable interface {
	AddRoute(dst netip.Prefix) error
	DelRoute(dst netip.Prefix) error
}

// sourcedRouteTable is the optional extension a datapath implements when it can
// pin a route's preferred source address. Only the kernel datapaths need it:
// netstack sources from the binding it was given, but the kernel picks by
// longest matching prefix across every address on the device, and an agent
// connected to several relays carries one address per relay there. Without a
// pinned source the kernel can hand a packet the address of a relay other than
// the one the route egresses to, and relays do not federate — so it is dropped.
type sourcedRouteTable interface {
	AddRouteSrc(dst netip.Prefix, src netip.Addr) error
}

// routeOwner identifies whoever claims a set of transit prefixes. Sessions use
// their connection slot's relay address, which is unique across live sessions
// by construction (RandAllocator hands each slot a distinct relay).
type routeOwner string

// routeReconciler owns the router's transit route table on behalf of every
// session in the agent.
//
// Two properties force this to live above the session rather than inside it:
//
//   - The router is created once per agent and outlives sessions, so routes a
//     session installs survive it. Diffing against the session's own view of
//     the world leaves anything it installed but never saw again — a prefix
//     advertised in one session and absent from the next is never withdrawn,
//     and keeps pointing at a tunnel device that no longer carries it.
//   - With MinConns > 1 several sessions share the router, each polling its own
//     relay. Their route sets overlap but are not equal, so a session applying
//     its own set as the whole truth would withdraw prefixes another session
//     still needs.
//
// So the reconciler tracks each owner's claim and drives the router to the
// union: a prefix is installed while at least one owner claims it, and removed
// once the last claim goes away.
type routeReconciler struct {
	rt routeTable
	// srcRT is rt again when the datapath can pin source addresses, nil when it
	// cannot. Resolved once so the hot path does not re-assert.
	srcRT sourcedRouteTable
	// installable filters prefixes the datapath refuses to carry. Default
	// routes are netstack-only (see initRouter); on a TUN device they would
	// shadow the netns default route.
	installable func(netip.Prefix) bool

	mu sync.Mutex
	// claims is the per-owner desired set. Absent owner == claims nothing.
	claims map[routeOwner]routeClaim
	// installed maps each prefix the router has been told about to the source
	// address it was programmed with (invalid when none was pinned). Tracked
	// rather than recomputed so a failed AddRoute is retried on the next
	// reconcile instead of being recorded as present, and so a prefix whose
	// source changed owners is reprogrammed rather than left stale.
	installed map[netip.Prefix]netip.Addr
}

// routeClaim is one owner's desired prefixes together with the source addresses
// traffic to them should carry — the owner's own overlay addresses on the relay
// that advertised them.
type routeClaim struct {
	src      routeSource
	prefixes sets.Set[netip.Prefix]
}

// routeSource is a session's overlay addresses, one per family. Both are needed:
// the kernel carries a route's preferred source in the route's own address
// family, and an agent holds a 100.64/10 address alongside its ULA on every
// relay it is connected to, so an IPv4 route left unsourced is as free to pick
// another relay's v4 address as an IPv6 one is to pick another relay's ULA.
type routeSource struct {
	v4 netip.Addr
	v6 netip.Addr
}

// forDst returns the address to pin on a route to dst: the one of dst's own
// family, or the zero Addr when the session holds none.
func (s routeSource) forDst(dst netip.Prefix) netip.Addr {
	src := s.v6
	if dst.Addr().Is4() {
		src = s.v4
	}
	if !src.IsValid() || src.Is4() != dst.Addr().Is4() {
		return netip.Addr{}
	}
	return src
}

// newRouteReconciler wraps rt. installed is what the caller has already
// programmed into the router — the bootstrap ConnectResponse's routes, which
// initRouter installs before any session exists. They are recorded as installed
// but unclaimed, so the first session to Claim makes its own set authoritative:
// prefixes it also wants stay put with no churn, and prefixes it does not are
// withdrawn instead of lingering for the agent's lifetime.
func newRouteReconciler(
	rt routeTable,
	installable func(netip.Prefix) bool,
	installed map[netip.Prefix]netip.Addr,
) *routeReconciler {
	if installed == nil {
		installed = make(map[netip.Prefix]netip.Addr)
	}
	srcRT, _ := rt.(sourcedRouteTable)
	return &routeReconciler{
		rt:          rt,
		srcRT:       srcRT,
		installable: installable,
		claims:      make(map[routeOwner]routeClaim),
		installed:   installed,
	}
}

// Claim replaces owner's claimed prefix set and reconciles the router to the
// new union. Passing an empty set (or calling Release) withdraws the owner's
// claims without disturbing prefixes another owner still wants.
func (rr *routeReconciler) Claim(owner routeOwner, src routeSource, desired sets.Set[netip.Prefix]) {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	if desired.Len() == 0 {
		delete(rr.claims, owner)
	} else {
		rr.claims[owner] = routeClaim{src: src, prefixes: desired}
	}
	rr.reconcileLocked()
}

// Release withdraws every claim held by owner. Call it when a session ends so
// its transit prefixes do not outlive the tunnel that carried them.
func (rr *routeReconciler) Release(owner routeOwner) {
	rr.Claim(owner, routeSource{}, sets.New[netip.Prefix]())
}

// reconcileLocked drives the router toward the union of all claims.
func (rr *routeReconciler) reconcileLocked() {
	want := make(map[netip.Prefix]netip.Addr)
	// Owners are visited in sorted order so the outcome does not flap with map
	// iteration order.
	for _, owner := range slices.Sorted(maps.Keys(rr.claims)) {
		claim := rr.claims[owner]
		for dst := range claim.prefixes {
			if rr.installable != nil && !rr.installable(dst) {
				continue
			}
			src := claim.src.forDst(dst)
			if cur, dup := want[dst]; dup {
				// Contested: more than one session advertises this prefix, so
				// no single session's address is the right source for it —
				// pinning one would send traffic destined for another relay's
				// space out the wrong session. Leaving it unsourced hands the
				// choice back to the kernel, which since the slot moved to the
				// high bits picks the longest match — i.e. the destination's
				// own relay — on its own. Relays advertise per-relay /88s and
				// keep the network-wide /72 to themselves, so this is a
				// backstop for prefixes genuinely reachable through more than
				// one relay (a transit CIDR behind two agents, say), not the
				// common path.
				if cur != src {
					want[dst] = netip.Addr{}
				}
				continue
			}
			want[dst] = src
		}
	}

	for dst, src := range want {
		if cur, ok := rr.installed[dst]; ok && cur == src {
			continue
		}
		attrs := []any{slog.String("destination", dst.String())}
		if src.IsValid() {
			attrs = append(attrs, slog.String("source", src.String()))
		}
		slog.Info("Adding route", attrs...)
		if err := rr.addRoute(dst, src); err != nil {
			slog.Warn("Failed to add route",
				slog.String("prefix", dst.String()),
				slog.Any("error", err))
			continue
		}
		rr.installed[dst] = src
	}

	for dst := range rr.installed {
		if _, ok := want[dst]; ok {
			continue
		}
		slog.Info("Removing route", slog.String("destination", dst.String()))
		if err := rr.rt.DelRoute(dst); err != nil {
			slog.Warn("Failed to remove route",
				slog.String("prefix", dst.String()),
				slog.Any("error", err))
			// Drop it from installed regardless: the claim is gone, so
			// retrying forever would pin a prefix nobody wants. A route the
			// kernel already lost is the common cause.
		}
		delete(rr.installed, dst)
	}
}

// addRoute programs dst, pinning src when both the datapath supports it and the
// claim carried one. A datapath that cannot pin sources still gets the route:
// netstack does not need one, and a kernel datapath with an unsourced route is
// no worse off than before.
func (rr *routeReconciler) addRoute(dst netip.Prefix, src netip.Addr) error {
	if rr.srcRT != nil && src.IsValid() {
		return rr.srcRT.AddRouteSrc(dst, src)
	}
	return rr.rt.AddRoute(dst)
}
