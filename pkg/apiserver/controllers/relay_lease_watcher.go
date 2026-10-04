package controllers

import (
	"context"
	"log/slog"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apoxycoordv1 "github.com/apoxy-dev/apoxy/api/coordination/v1"
	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	tunnelctrl "github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
)

const (
	// defaultRelayLeaseDuration is how long a lease is live after renewal. The
	// lease's own LeaseDurationSeconds is ignored.
	defaultRelayLeaseDuration = 40 * time.Second

	// defaultRelayGracePeriod is how long a dead relay is kept before deletion.
	defaultRelayGracePeriod = 60 * time.Second

	// defaultRelayLeaseCheckInterval is how often a lease is checked again. A
	// lease that stops renewal sends no watch event.
	defaultRelayLeaseCheckInterval = 10 * time.Second
)

var _ reconcile.Reconciler = &RelayLeaseWatcher{}

// RelayLeaseWatcher sets Relay.Status.Ready from the relay's Lease. When the
// Lease is gone or expired past the grace period, it deletes the Relay, its
// Tunnels and the Lease.
type RelayLeaseWatcher struct {
	client.Client

	leaseNamespace string
	leaseDuration  time.Duration
	gracePeriod    time.Duration
	checkInterval  time.Duration
	now            func() time.Time
	// startedAt is when this apiserver started. A relay cannot renew its lease
	// before it, so that time does not count as lease age.
	startedAt time.Time
}

// RelayLeaseWatcherOption configures a RelayLeaseWatcher.
type RelayLeaseWatcherOption func(*RelayLeaseWatcher)

// WithRelayLeaseNamespace sets the namespace of relay Leases. Leases in other
// namespaces are ignored.
func WithRelayLeaseNamespace(ns string) RelayLeaseWatcherOption {
	return func(w *RelayLeaseWatcher) { w.leaseNamespace = ns }
}

// WithRelayLeaseDuration sets how long a lease is live after renewal.
func WithRelayLeaseDuration(d time.Duration) RelayLeaseWatcherOption {
	return func(w *RelayLeaseWatcher) { w.leaseDuration = d }
}

// WithRelayGracePeriod sets how long a dead relay is kept before deletion.
func WithRelayGracePeriod(d time.Duration) RelayLeaseWatcherOption {
	return func(w *RelayLeaseWatcher) { w.gracePeriod = d }
}

// WithRelayLeaseCheckInterval sets how often a lease is checked again.
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
		startedAt:      time.Now(),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// relayNameFromLease returns the Relay name of a lease, or "" for other leases.
func relayNameFromLease(name string) string {
	if !strings.HasPrefix(name, tunnelctrl.LeaseNamePrefix) {
		return ""
	}
	return strings.TrimPrefix(name, tunnelctrl.LeaseNamePrefix)
}

// leaseAge returns the time since the last renewal, without the time before
// since. ok is false when the lease has no RenewTime.
func leaseAge(lease *apoxycoordv1.Lease, since, now time.Time) (age time.Duration, ok bool) {
	if lease.Spec.RenewTime == nil {
		return 0, false
	}
	renewed := lease.Spec.RenewTime.Time
	if renewed.Before(since) {
		renewed = since
	}
	return now.Sub(renewed), true
}

// Reconcile sets Relay readiness from its Lease and deletes a dead relay.
func (w *RelayLeaseWatcher) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	relayName := relayNameFromLease(req.Name)
	if relayName == "" || req.Namespace != w.leaseNamespace {
		return reconcile.Result{}, nil
	}

	var lease apoxycoordv1.Lease
	err := w.Get(ctx, req.NamespacedName, &lease)
	if apierrors.IsNotFound(err) {
		slog.Info("Relay lease is gone; deleting Relay",
			"lease", req.NamespacedName, "relay", relayName)
		if err := w.deleteRelay(ctx, relayName); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, w.deleteTunnelsForRelay(ctx, relayName)
	}
	if err != nil {
		return reconcile.Result{}, err
	}

	age, ok := leaseAge(&lease, w.startedAt, w.now())
	alive := ok && age <= w.leaseDuration

	if err := w.setReady(ctx, relayName, alive); err != nil {
		return reconcile.Result{}, err
	}

	if alive {
		return reconcile.Result{RequeueAfter: w.checkInterval}, nil
	}

	// A lease without RenewTime is never deleted.
	if ok && age > w.leaseDuration+w.gracePeriod {
		slog.Info("Relay lease expired past its grace period; removing relay state",
			"lease", req.NamespacedName, "relay", relayName, "age", age)
		if err := w.deleteRelay(ctx, relayName); err != nil {
			return reconcile.Result{}, err
		}
		if err := w.deleteTunnelsForRelay(ctx, relayName); err != nil {
			return reconcile.Result{}, err
		}
		if err := w.Delete(ctx, &lease); err != nil && !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, nil
	}
	return reconcile.Result{RequeueAfter: w.checkInterval}, nil
}

// setReady writes Relay readiness only when it changes. A missing Relay is not
// an error.
func (w *RelayLeaseWatcher) setReady(ctx context.Context, relayName string, ready bool) error {
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
	slog.Info("Updated Relay readiness", "relay", relayName, "ready", ready)
	return nil
}

func (w *RelayLeaseWatcher) deleteRelay(ctx context.Context, relayName string) error {
	relay := &vpcv1alpha1.Relay{}
	relay.SetName(relayName)
	return client.IgnoreNotFound(w.Delete(ctx, relay))
}

// deleteTunnelsForRelay deletes all Tunnels labeled with the relay, also the
// slot-owned ones. A slot lease keeps only the addresses.
func (w *RelayLeaseWatcher) deleteTunnelsForRelay(ctx context.Context, relayName string) error {
	return w.DeleteAllOf(ctx, &vpcv1alpha1.Tunnel{}, client.MatchingLabels{tunnelctrl.LabelRelay: relayName})
}

// SetupWithManager registers the watcher for relay Leases.
func (w *RelayLeaseWatcher) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("relay-lease-watcher").
		For(&apoxycoordv1.Lease{}, builder.WithPredicates(w.relayLeasePredicate())).
		Complete(w)
}

func (w *RelayLeaseWatcher) relayLeasePredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return relayNameFromLease(obj.GetName()) != "" && obj.GetNamespace() == w.leaseNamespace
	})
}
