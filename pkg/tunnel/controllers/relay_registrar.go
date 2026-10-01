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
	// LeaseNamePrefix keeps relay Leases apart from other Leases in the same
	// namespace. The lease watcher strips it to find the Relay.
	LeaseNamePrefix = "relay-"

	// DefaultLeaseNamespace is where relay Leases live when none is configured.
	DefaultLeaseNamespace = "default"

	// defaultRenewInterval is well under half the lease duration, so one missed
	// renewal does not expire the lease.
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

// leaseDurationSeconds rounds a lease duration to whole seconds, at least 1.
func leaseDurationSeconds(d time.Duration) int32 {
	s := int32(d.Round(time.Second) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}

// RelayRegistrar creates the write-once Relay object and renews its Lease, so
// the lease watcher can mark a crashed relay not ready.
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
	onRenew        func(restored bool)
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

// WithOnRenew sets a callback that runs after each registration or renewal.
// restored is true when the apiserver can have lost this relay's Tunnels.
func WithOnRenew(fn func(restored bool)) RegistrarOption {
	return func(r *RelayRegistrar) { r.onRenew = fn }
}

// WithLeaseDuration overrides the advertised lease duration.
func WithLeaseDuration(d time.Duration) RegistrarOption {
	return func(r *RelayRegistrar) { r.leaseDuration = d }
}

// NewRelayRegistrar creates a RelayRegistrar. A nil networkSelector selects all
// networks.
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
	r.renewed(true)

	ticker := time.NewTicker(r.renewInterval)
	defer ticker.Stop()

	failed := false
	for {
		select {
		case <-ctx.Done():
			slog.Info("Relay registrar shutting down", "relay", r.relay.Name())
			return ctx.Err()
		case <-ticker.C:
			relayCreated, err := r.ensureRelay(ctx)
			if err != nil {
				slog.Warn("Failed to restore relay registration", "relay", r.relay.Name(), "error", err)
			}
			leaseCreated, leaseErr := r.renewLease(ctx)
			if leaseErr != nil {
				slog.Warn("Failed to renew relay lease", "relay", r.relay.Name(), "error", leaseErr)
			}
			if err == nil && leaseErr == nil {
				r.renewed(failed || relayCreated || leaseCreated)
			}
			failed = err != nil || leaseErr != nil
		}
	}
}

func (r *RelayRegistrar) renewed(restored bool) {
	if r.onRenew != nil {
		r.onRenew(restored)
	}
}

// registerWithRetry ensures the Relay object and an initial lease exist,
// retrying with exponential backoff until it succeeds or ctx is canceled.
func (r *RelayRegistrar) registerWithRetry(ctx context.Context) error {
	delay := initialRetryDelay
	for {
		if _, err := r.ensureRelay(ctx); err == nil {
			if _, err := r.renewLease(ctx); err == nil {
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

// ensureRelay creates the write-once Relay object if it does not exist, and
// reports whether it did.
func (r *RelayRegistrar) ensureRelay(ctx context.Context) (bool, error) {
	existing := &vpcv1alpha1.Relay{}
	err := r.relayClient.Get(ctx, client.ObjectKey{Name: r.relay.Name()}, existing)
	if err == nil {
		return false, nil
	}
	if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get relay: %w", err)
	}
	return true, r.createRelay(ctx)
}

func (r *RelayRegistrar) createRelay(ctx context.Context) error {
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

// renewLease creates or renews the relay's Lease, and reports whether it
// created it.
func (r *RelayRegistrar) renewLease(ctx context.Context) (bool, error) {
	now := metav1.NewMicroTime(r.now())
	key := client.ObjectKey{Namespace: r.leaseNamespace, Name: LeaseName(r.relay.Name())}

	existing := &apoxycoordv1.Lease{}
	err := r.leaseClient.Get(ctx, key, existing)
	if apierrors.IsNotFound(err) {
		return true, r.createLease(ctx, now)
	}
	if err != nil {
		return false, fmt.Errorf("failed to get lease: %w", err)
	}

	existing.Spec.HolderIdentity = ptr.To(r.relay.Name())
	existing.Spec.LeaseDurationSeconds = ptr.To(leaseDurationSeconds(r.leaseDuration))
	existing.Spec.RenewTime = &now
	if existing.Spec.AcquireTime == nil {
		existing.Spec.AcquireTime = &now
	}
	if err := r.leaseClient.Update(ctx, existing); apierrors.IsNotFound(err) {
		// A restored apiserver can lose recent objects that the informer cache still
		// has, so write both again.
		if err := r.createRelay(ctx); err != nil {
			return false, fmt.Errorf("failed to restore relay: %w", err)
		}
		return true, r.createLease(ctx, now)
	} else if err != nil {
		return false, fmt.Errorf("failed to renew lease: %w", err)
	}
	return false, nil
}

func (r *RelayRegistrar) createLease(ctx context.Context, now metav1.MicroTime) error {
	lease := &apoxycoordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: r.leaseNamespace, Name: LeaseName(r.relay.Name())},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptr.To(r.relay.Name()),
			LeaseDurationSeconds: ptr.To(leaseDurationSeconds(r.leaseDuration)),
			AcquireTime:          &now,
			RenewTime:            &now,
		},
	}
	if err := r.leaseClient.Create(ctx, lease); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create lease: %w", err)
	}
	return nil
}

// Drain deletes the relay's Lease and Relay objects. Wire it to
// Relay.SetOnShutdown; it does not stop the renewal loop.
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
