package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apoxycoordv1 "github.com/apoxy-dev/apoxy/api/coordination/v1"
	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

const (
	// LeaseNamePrefix is prepended to a relay's name to form its Lease name.
	// Relays are cluster-scoped but Leases are namespaced and shared with other
	// coordination.apoxy.dev consumers (e.g. leader election), so the prefix
	// keeps relay leases in their own namespace and avoids collisions. The lease
	// watcher strips it to resolve the owning Relay.
	LeaseNamePrefix = "relay-"

	// DefaultLeaseNamespace is where relay Leases live when none is configured.
	DefaultLeaseNamespace = "default"

	// defaultRenewInterval is how often the registrar renews its lease. It must
	// be well under half the lease duration so a single missed renewal does not
	// expire the lease (mirrors the endpoint registrar's 20s/40s cadence).
	defaultRenewInterval = 20 * time.Second

	// defaultLeaseDuration is the lease validity window the watcher enforces.
	defaultLeaseDuration = 40 * time.Second

	// initialRetryDelay / maxRetryDelay bound the registration backoff.
	initialRetryDelay = 5 * time.Second
	maxRetryDelay     = 60 * time.Second
)

// LeaseName returns the Lease name for a relay of the given name.
func LeaseName(relayName string) string {
	return LeaseNamePrefix + relayName
}

// leaseDurationSeconds renders a lease duration as whole seconds for the
// coordination Lease field, rounding to the nearest second and flooring at 1 so
// a sub-second duration never truncates to 0 (which downstream consumers would
// read as "already expired").
func leaseDurationSeconds(d time.Duration) int32 {
	s := int32(d.Round(time.Second) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}

// RelayRegistrar owns a relay's presence in the control plane: it creates the
// write-once Relay object on start and renews a coordination.apoxy.dev Lease on
// a fixed cadence so the lease watcher can flip Relay readiness on crash. On
// drain it flips readiness off and deletes both objects (§2.3/§5).
//
// It takes two clients so the same implementation serves OSS (both point at the
// standalone apiserver) and cloud cmd/relay (leaseClient -> infra-apiz,
// relayClient -> shard fan-out). This is the cmd/relay seam.
type RelayRegistrar struct {
	leaseClient     client.Client
	relayClient     client.Client
	relay           Relay
	addresses       []string
	networkSelector *metav1.LabelSelector

	leaseNamespace string
	renewInterval  time.Duration
	leaseDuration  time.Duration
	now            func() time.Time
}

// RegistrarOption configures a RelayRegistrar.
type RegistrarOption func(*RelayRegistrar)

// WithLeaseNamespace overrides the namespace relay Leases are written to.
func WithLeaseNamespace(ns string) RegistrarOption {
	return func(r *RelayRegistrar) { r.leaseNamespace = ns }
}

// WithRenewInterval overrides the lease renewal cadence.
func WithRenewInterval(d time.Duration) RegistrarOption {
	return func(r *RelayRegistrar) { r.renewInterval = d }
}

// WithLeaseDuration overrides the advertised lease duration.
func WithLeaseDuration(d time.Duration) RegistrarOption {
	return func(r *RelayRegistrar) { r.leaseDuration = d }
}

// NewRelayRegistrar creates a RelayRegistrar. addresses are the underlay
// endpoints agents dial; networkSelector scopes which networks the relay serves
// (nil selects all).
func NewRelayRegistrar(
	leaseClient, relayClient client.Client,
	relay Relay,
	addresses []string,
	networkSelector *metav1.LabelSelector,
	opts ...RegistrarOption,
) *RelayRegistrar {
	r := &RelayRegistrar{
		leaseClient:     leaseClient,
		relayClient:     relayClient,
		relay:           relay,
		addresses:       addresses,
		networkSelector: networkSelector,
		leaseNamespace:  DefaultLeaseNamespace,
		renewInterval:   defaultRenewInterval,
		leaseDuration:   defaultLeaseDuration,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Start registers the Relay (write-once) then renews the lease until ctx is
// canceled. It implements manager.Runnable so it can be added to a manager.
func (r *RelayRegistrar) Start(ctx context.Context) error {
	if err := r.registerWithRetry(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(r.renewInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Relay registrar shutting down", "relay", r.relay.Name())
			return ctx.Err()
		case <-ticker.C:
			if err := r.renewLease(ctx); err != nil {
				slog.Warn("Failed to renew relay lease", "relay", r.relay.Name(), "error", err)
			}
		}
	}
}

// registerWithRetry ensures the Relay object and an initial lease exist,
// retrying with exponential backoff until it succeeds or ctx is canceled.
func (r *RelayRegistrar) registerWithRetry(ctx context.Context) error {
	delay := initialRetryDelay
	for {
		if err := r.ensureRelay(ctx); err == nil {
			if err := r.renewLease(ctx); err == nil {
				slog.Info("Relay registered", "relay", r.relay.Name())
				return nil
			} else {
				slog.Warn("Failed to acquire relay lease, retrying", "relay", r.relay.Name(), "delay", delay, "error", err)
			}
		} else {
			slog.Warn("Failed to register relay, retrying", "relay", r.relay.Name(), "delay", delay, "error", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			delay = min(delay*2, maxRetryDelay)
		}
	}
}

// ensureRelay creates the write-once Relay object if it does not exist. The
// spec is never mutated once created: liveness lives in the lease, not here.
func (r *RelayRegistrar) ensureRelay(ctx context.Context) error {
	existing := &vpcv1alpha1.Relay{}
	err := r.relayClient.Get(ctx, client.ObjectKey{Name: r.relay.Name()}, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get relay: %w", err)
	}

	relay := &vpcv1alpha1.Relay{
		ObjectMeta: metav1.ObjectMeta{Name: r.relay.Name()},
		Spec: vpcv1alpha1.RelaySpec{
			Addresses:       r.addresses,
			NetworkSelector: r.networkSelector,
		},
	}
	if err := r.relayClient.Create(ctx, relay); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("failed to create relay: %w", err)
	}
	slog.Info("Created relay object", "relay", r.relay.Name())
	return nil
}

// renewLease creates or renews the relay's Lease, stamping a fresh RenewTime.
func (r *RelayRegistrar) renewLease(ctx context.Context) error {
	now := metav1.NewMicroTime(r.now())
	key := client.ObjectKey{Namespace: r.leaseNamespace, Name: LeaseName(r.relay.Name())}

	existing := &apoxycoordv1.Lease{}
	err := r.leaseClient.Get(ctx, key, existing)
	if apierrors.IsNotFound(err) {
		lease := &apoxycoordv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Namespace: r.leaseNamespace, Name: key.Name},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       ptr.To(r.relay.Name()),
				LeaseDurationSeconds: ptr.To(leaseDurationSeconds(r.leaseDuration)),
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}
		if err := r.leaseClient.Create(ctx, lease); err != nil {
			return fmt.Errorf("failed to create lease: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get lease: %w", err)
	}

	existing.Spec.HolderIdentity = ptr.To(r.relay.Name())
	existing.Spec.LeaseDurationSeconds = ptr.To(int32(r.leaseDuration.Seconds()))
	existing.Spec.RenewTime = &now
	if existing.Spec.AcquireTime == nil {
		existing.Spec.AcquireTime = &now
	}
	if err := r.leaseClient.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to renew lease: %w", err)
	}
	return nil
}

// Drain tears down the relay's control-plane presence by deleting its Lease and
// Relay objects (§5). Deletion is the terminal signal consumers act on; there is
// no separate ready=false write, since Drain runs synchronously at shutdown with
// no settle window in which an intermediate not-ready state could be observed.
// It is meant to be wired to Relay.SetOnShutdown by the caller; it does not stop
// the renewal loop itself (canceling Start's ctx does that).
func (r *RelayRegistrar) Drain(ctx context.Context) {
	lease := &apoxycoordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: r.leaseNamespace, Name: LeaseName(r.relay.Name())},
	}
	if err := r.leaseClient.Delete(ctx, lease); err != nil && !apierrors.IsNotFound(err) {
		slog.Error("Failed to delete relay lease during drain", "relay", r.relay.Name(), "error", err)
	}

	relay := &vpcv1alpha1.Relay{ObjectMeta: metav1.ObjectMeta{Name: r.relay.Name()}}
	if err := r.relayClient.Delete(ctx, relay); err != nil && !apierrors.IsNotFound(err) {
		slog.Error("Failed to delete relay object during drain", "relay", r.relay.Name(), "error", err)
	}
}
