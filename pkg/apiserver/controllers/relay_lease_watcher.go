package controllers

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apoxycoordv1 "github.com/apoxy-dev/apoxy/api/coordination/v1"
	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	tunnelctrl "github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
)

const (
	// defaultRelayLeaseDuration is how long a relay lease is considered live
	// after its last renewal. The watcher is the sole authority on staleness; it
	// does NOT trust the lease's self-advertised LeaseDurationSeconds, so a buggy
	// relay cannot widen its own liveness window.
	defaultRelayLeaseDuration = 40 * time.Second

	// defaultRelayGracePeriod is how long past expiry a relay is kept (marked
	// not-ready) before it and its stale lease are garbage-collected. It gives a
	// crashed relay a window to recover (network blip) before its objects are
	// reclaimed.
	defaultRelayGracePeriod = 60 * time.Second

	// defaultRelayLeaseCheckInterval bounds how long an expiry goes unnoticed:
	// the watcher requeues non-terminal leases this often to re-check staleness,
	// since a lease that simply stops being renewed produces no watch event.
	defaultRelayLeaseCheckInterval = 10 * time.Second
)

var _ reconcile.Reconciler = &RelayLeaseWatcher{}

// RelayLeaseWatcher reconciles relay liveness from the coordination.apoxy.dev
// Lease each relay renews. It flips Relay.Status.Ready on liveness transitions
// only (crash -> not ready, recovery -> ready) and garbage-collects the Relay
// object and its stale lease once the lease has been expired past the grace
// period (§2.3) — a crashed relay never deletes its own lease, so expiry, not
// deletion, is the signal that reclaims it. Orphan-Tunnel GC keyed on the
// vanished relay lands in phase 5, when the connect path first creates Tunnels.
type RelayLeaseWatcher struct {
	client.Client

	leaseNamespace string
	leaseDuration  time.Duration
	gracePeriod    time.Duration
	checkInterval  time.Duration
	now            func() time.Time
}

// RelayLeaseWatcherOption configures a RelayLeaseWatcher.
type RelayLeaseWatcherOption func(*RelayLeaseWatcher)

// WithRelayLeaseNamespace restricts the watcher to leases in the given
// namespace — the same namespace the registrar writes to. Relays are
// cluster-scoped, so without this a relay-prefixed lease deleted in any
// namespace would map onto (and delete) the like-named Relay.
func WithRelayLeaseNamespace(ns string) RelayLeaseWatcherOption {
	return func(w *RelayLeaseWatcher) { w.leaseNamespace = ns }
}

// WithRelayLeaseDuration overrides the staleness window.
func WithRelayLeaseDuration(d time.Duration) RelayLeaseWatcherOption {
	return func(w *RelayLeaseWatcher) { w.leaseDuration = d }
}

// WithRelayGracePeriod overrides how long past expiry a relay is kept before GC.
func WithRelayGracePeriod(d time.Duration) RelayLeaseWatcherOption {
	return func(w *RelayLeaseWatcher) { w.gracePeriod = d }
}

// WithRelayLeaseCheckInterval overrides the re-check cadence for pending leases.
func WithRelayLeaseCheckInterval(d time.Duration) RelayLeaseWatcherOption {
	return func(w *RelayLeaseWatcher) { w.checkInterval = d }
}

// NewRelayLeaseWatcher creates a RelayLeaseWatcher.
func NewRelayLeaseWatcher(c client.Client, opts ...RelayLeaseWatcherOption) *RelayLeaseWatcher {
	w := &RelayLeaseWatcher{
		Client:         c,
		leaseNamespace: tunnelctrl.DefaultLeaseNamespace,
		leaseDuration:  defaultRelayLeaseDuration,
		gracePeriod:    defaultRelayGracePeriod,
		checkInterval:  defaultRelayLeaseCheckInterval,
		now:            time.Now,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// relayNameFromLease returns the Relay name a lease belongs to, or "" if the
// lease is not a relay lease.
func relayNameFromLease(name string) string {
	if !strings.HasPrefix(name, tunnelctrl.LeaseNamePrefix) {
		return ""
	}
	return strings.TrimPrefix(name, tunnelctrl.LeaseNamePrefix)
}

// leaseAge returns how long ago the lease was last renewed. ok is false when
// the lease carries no RenewTime (malformed / mid-creation), in which case the
// caller must not garbage-collect on age.
func leaseAge(lease *apoxycoordv1.Lease, now time.Time) (age time.Duration, ok bool) {
	if lease.Spec.RenewTime == nil {
		return 0, false
	}
	return now.Sub(lease.Spec.RenewTime.Time), true
}

// Reconcile flips the owning Relay's readiness to match its lease liveness and
// garbage-collects the Relay (and stale lease) once expired past the grace.
func (w *RelayLeaseWatcher) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := controllerlog.FromContext(ctx).WithValues("lease", req.NamespacedName)

	relayName := relayNameFromLease(req.Name)
	if relayName == "" || req.Namespace != w.leaseNamespace {
		return reconcile.Result{}, nil
	}

	var lease apoxycoordv1.Lease
	err := w.Get(ctx, req.NamespacedName, &lease)
	if apierrors.IsNotFound(err) {
		// Lease already gone (e.g. graceful drain deleted it): GC the Relay.
		log.Info("Relay lease gone, deleting relay", "relay", relayName)
		return reconcile.Result{}, w.deleteRelay(ctx, relayName)
	}
	if err != nil {
		return reconcile.Result{}, err
	}

	age, ok := leaseAge(&lease, w.now())
	alive := ok && age <= w.leaseDuration

	// Reflect liveness onto the Relay (transitions only).
	if err := w.setReady(ctx, log, relayName, alive); err != nil {
		return reconcile.Result{}, err
	}

	if alive {
		return reconcile.Result{RequeueAfter: w.checkInterval}, nil
	}

	// Dead: GC once expired past the grace period; otherwise revisit later. A
	// missing RenewTime (ok == false) never GCs — it is treated as pending.
	if ok && age > w.leaseDuration+w.gracePeriod {
		log.Info("Relay lease expired past grace, garbage-collecting", "relay", relayName, "age", age.String())
		if err := w.deleteRelay(ctx, relayName); err != nil {
			return reconcile.Result{}, err
		}
		if err := w.Delete(ctx, &lease); err != nil && !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, nil
	}
	return reconcile.Result{RequeueAfter: w.checkInterval}, nil
}

// setReady updates the Relay's readiness only when it actually changes. A
// missing Relay (not created yet, or already GC'd) is not an error.
func (w *RelayLeaseWatcher) setReady(ctx context.Context, log logr.Logger, relayName string, ready bool) error {
	var relay vpcv1alpha1.Relay
	if err := w.Get(ctx, client.ObjectKey{Name: relayName}, &relay); err != nil {
		return client.IgnoreNotFound(err)
	}
	if relay.Status.Ready == ready {
		return nil
	}
	relay.Status.Ready = ready
	if err := w.Status().Update(ctx, &relay); err != nil {
		return err
	}
	log.Info("Flipped relay readiness", "relay", relayName, "ready", ready)
	return nil
}

// deleteRelay removes the cluster-scoped Relay object, tolerating a concurrent
// delete (graceful drain races the watcher).
func (w *RelayLeaseWatcher) deleteRelay(ctx context.Context, relayName string) error {
	relay := &vpcv1alpha1.Relay{}
	relay.SetName(relayName)
	return client.IgnoreNotFound(w.Delete(ctx, relay))
}

// SetupWithManager wires the watcher to relay Leases only.
func (w *RelayLeaseWatcher) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("relay-lease-watcher").
		For(&apoxycoordv1.Lease{}, builder.WithPredicates(w.relayLeasePredicate())).
		Complete(w)
}

// relayLeasePredicate restricts the watch to relay leases in the watcher's
// namespace (by name prefix + namespace).
func (w *RelayLeaseWatcher) relayLeasePredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return relayNameFromLease(obj.GetName()) != "" && obj.GetNamespace() == w.leaseNamespace
	})
}
