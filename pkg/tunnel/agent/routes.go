package agent

import (
	"log/slog"
	"net/netip"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

// routeTable is the slice of router.Router the reconciler needs. Narrowing it
// keeps the reconciler testable without standing up a datapath.
type routeTable interface {
	AddRoute(dst netip.Prefix) error
	DelRoute(dst netip.Prefix) error
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
	// installable filters prefixes the datapath refuses to carry. Default
	// routes are netstack-only (see initRouter); on a TUN device they would
	// shadow the netns default route.
	installable func(netip.Prefix) bool

	mu sync.Mutex
	// claims is the per-owner desired set. Absent owner == claims nothing.
	claims map[routeOwner]sets.Set[netip.Prefix]
	// installed is what the router has been told about, i.e. the union of
	// claims minus anything filtered out. Tracked rather than recomputed so a
	// failed AddRoute is retried on the next reconcile instead of being
	// recorded as present.
	installed sets.Set[netip.Prefix]
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
	installed sets.Set[netip.Prefix],
) *routeReconciler {
	if installed == nil {
		installed = sets.New[netip.Prefix]()
	}
	return &routeReconciler{
		rt:          rt,
		installable: installable,
		claims:      make(map[routeOwner]sets.Set[netip.Prefix]),
		installed:   installed,
	}
}

// Claim replaces owner's claimed prefix set and reconciles the router to the
// new union. Passing an empty set (or calling Release) withdraws the owner's
// claims without disturbing prefixes another owner still wants.
func (rr *routeReconciler) Claim(owner routeOwner, desired sets.Set[netip.Prefix]) {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	if desired.Len() == 0 {
		delete(rr.claims, owner)
	} else {
		rr.claims[owner] = desired
	}
	rr.reconcileLocked()
}

// Release withdraws every claim held by owner. Call it when a session ends so
// its transit prefixes do not outlive the tunnel that carried them.
func (rr *routeReconciler) Release(owner routeOwner) {
	rr.Claim(owner, sets.New[netip.Prefix]())
}

// reconcileLocked drives the router toward the union of all claims.
func (rr *routeReconciler) reconcileLocked() {
	want := sets.New[netip.Prefix]()
	for _, claim := range rr.claims {
		for dst := range claim {
			if rr.installable == nil || rr.installable(dst) {
				want.Insert(dst)
			}
		}
	}

	for dst := range want.Difference(rr.installed) {
		slog.Info("Adding route", slog.String("destination", dst.String()))
		if err := rr.rt.AddRoute(dst); err != nil {
			slog.Warn("Failed to add route",
				slog.String("prefix", dst.String()),
				slog.Any("error", err))
			continue
		}
		rr.installed.Insert(dst)
	}

	for dst := range rr.installed.Difference(want) {
		slog.Info("Removing route", slog.String("destination", dst.String()))
		if err := rr.rt.DelRoute(dst); err != nil {
			slog.Warn("Failed to remove route",
				slog.String("prefix", dst.String()),
				slog.Any("error", err))
			// Drop it from installed regardless: the claim is gone, so
			// retrying forever would pin a prefix nobody wants. A route the
			// kernel already lost is the common cause.
		}
		rr.installed.Delete(dst)
	}
}
