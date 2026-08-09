package controllers

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	apoxycoordv1 "github.com/apoxy-dev/apoxy/api/coordination/v1"
	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

// stubRelay is a minimal controllers.Relay used to drive the registrar. Only
// Name is exercised; the setters are inert.
type stubRelay struct{ name string }

func (s stubRelay) Name() string                                                         { return s.name }
func (s stubRelay) Address() netip.AddrPort                                              { return netip.AddrPort{} }
func (s stubRelay) SetCredentials(string, string)                                        {}
func (s stubRelay) RemoveCredentials(string)                                             {}
func (s stubRelay) SetEgressGateway(bool)                                                {}
func (s stubRelay) SetOnConnect(func(context.Context, string, string, Connection) error) {}
func (s stubRelay) SetOnDisconnect(func(context.Context, string, string) error)          {}
func (s stubRelay) DisconnectConnection(string)                                          {}
func (s stubRelay) SetOnShutdown(func(context.Context))                                  {}

func registrarScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, vpcv1alpha1.Install(s))
	require.NoError(t, apoxycoordv1.Install(s))
	return s
}

func newRegistrar(t *testing.T, now time.Time, objs ...client.Object) (*RelayRegistrar, client.Client) {
	t.Helper()
	s := registrarScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&vpcv1alpha1.Relay{}).
		WithObjects(objs...).
		Build()
	r := NewRelayRegistrar(c, c, stubRelay{name: "r0"}, []string{"1.2.3.4:6081"}, nil)
	r.now = func() time.Time { return now }
	return r, c
}

type deleteLeaseOnUpdateClient struct {
	client.Client
	deleteOnNextUpdate bool
}

func (c *deleteLeaseOnUpdateClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*apoxycoordv1.Lease); ok && c.deleteOnNextUpdate {
		c.deleteOnNextUpdate = false
		lease := &apoxycoordv1.Lease{ObjectMeta: metav1.ObjectMeta{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		}}
		if err := c.Client.Delete(ctx, lease); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return apierrors.NewNotFound(schema.GroupResource{
			Group:    apoxycoordv1.GroupName,
			Resource: "leases",
		}, obj.GetName())
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestRelayRegistrarEnsureRelay(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	t.Run("creates write-once relay when absent", func(t *testing.T) {
		r, c := newRegistrar(t, now)
		require.NoError(t, r.ensureRelay(ctx))

		var got vpcv1alpha1.Relay
		require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "r0"}, &got))
		require.Equal(t, []string{"1.2.3.4:6081"}, got.Spec.Addresses)
	})

	t.Run("does not mutate an existing relay spec", func(t *testing.T) {
		existing := &vpcv1alpha1.Relay{
			ObjectMeta: metav1.ObjectMeta{Name: "r0"},
			Spec:       vpcv1alpha1.RelaySpec{Addresses: []string{"9.9.9.9:6081"}},
		}
		r, c := newRegistrar(t, now, existing)
		require.NoError(t, r.ensureRelay(ctx))

		var got vpcv1alpha1.Relay
		require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "r0"}, &got))
		require.Equal(t, []string{"9.9.9.9:6081"}, got.Spec.Addresses, "spec left untouched")
	})
}

func TestRelayRegistrarRenewLease(t *testing.T) {
	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0)

	t.Run("creates lease on first renew", func(t *testing.T) {
		r, c := newRegistrar(t, t0)
		require.NoError(t, r.renewLease(ctx))

		var lease apoxycoordv1.Lease
		require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: DefaultLeaseNamespace, Name: LeaseName("r0")}, &lease))
		require.NotNil(t, lease.Spec.RenewTime)
		require.Equal(t, t0.Unix(), lease.Spec.RenewTime.Unix())
		require.NotNil(t, lease.Spec.LeaseDurationSeconds)
		require.EqualValues(t, 40, *lease.Spec.LeaseDurationSeconds)
	})

	t.Run("bumps RenewTime on subsequent renew", func(t *testing.T) {
		r, c := newRegistrar(t, t0)
		require.NoError(t, r.renewLease(ctx))

		t1 := t0.Add(20 * time.Second)
		r.now = func() time.Time { return t1 }
		require.NoError(t, r.renewLease(ctx))

		var lease apoxycoordv1.Lease
		require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: DefaultLeaseNamespace, Name: LeaseName("r0")}, &lease))
		require.Equal(t, t1.Unix(), lease.Spec.RenewTime.Unix(), "RenewTime advanced")
		require.Equal(t, t0.Unix(), lease.Spec.AcquireTime.Unix(), "AcquireTime pinned to first acquire")
	})
}

func TestRelayRegistrarRecoversAfterRestoredObjectsDisappear(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	lease := &apoxycoordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: DefaultLeaseNamespace, Name: LeaseName("r0")},
	}
	_, base := newRegistrar(t, now, lease)
	leaseClient := &deleteLeaseOnUpdateClient{Client: base, deleteOnNextUpdate: true}
	r := NewRelayRegistrar(leaseClient, base, stubRelay{name: "r0"}, []string{"1.2.3.4:6081"}, nil)
	r.now = func() time.Time { return now }

	require.NoError(t, r.renewLease(ctx))

	var gotRelay vpcv1alpha1.Relay
	require.NoError(t, base.Get(ctx, client.ObjectKey{Name: "r0"}, &gotRelay))
	var gotLease apoxycoordv1.Lease
	require.NoError(t, base.Get(ctx, client.ObjectKey{
		Namespace: DefaultLeaseNamespace,
		Name:      LeaseName("r0"),
	}, &gotLease))
	require.Equal(t, now.Unix(), gotLease.Spec.RenewTime.Unix())
}

func TestRelayRegistrarRecreatesRelayDuringRenewal(t *testing.T) {
	r, c := newRegistrar(t, time.Unix(1_700_000_000, 0))
	r.renewInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Start(ctx)
	}()

	require.Eventually(t, func() bool {
		return c.Get(context.Background(), client.ObjectKey{Name: "r0"}, &vpcv1alpha1.Relay{}) == nil
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, c.Delete(context.Background(), &vpcv1alpha1.Relay{
		ObjectMeta: metav1.ObjectMeta{Name: "r0"},
	}))
	require.Eventually(t, func() bool {
		return c.Get(context.Background(), client.ObjectKey{Name: "r0"}, &vpcv1alpha1.Relay{}) == nil
	}, time.Second, 10*time.Millisecond)

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestRelayRegistrarSubSecondLeaseDuration(t *testing.T) {
	ctx := context.Background()
	r, c := newRegistrar(t, time.Unix(1_700_000_000, 0))
	r.leaseDuration = 500 * time.Millisecond
	require.NoError(t, r.renewLease(ctx))

	var lease apoxycoordv1.Lease
	require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: DefaultLeaseNamespace, Name: LeaseName("r0")}, &lease))
	require.EqualValues(t, 1, *lease.Spec.LeaseDurationSeconds, "sub-second duration floors at 1s, never 0")
}

func TestRelayRegistrarDrain(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	// Seed a ready relay plus its lease.
	relay := &vpcv1alpha1.Relay{
		ObjectMeta: metav1.ObjectMeta{Name: "r0"},
		Spec:       vpcv1alpha1.RelaySpec{Addresses: []string{"1.2.3.4:6081"}},
		Status:     vpcv1alpha1.RelayStatus{Ready: true},
	}
	lease := &apoxycoordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: DefaultLeaseNamespace, Name: LeaseName("r0")},
	}
	r, c := newRegistrar(t, now, relay, lease)

	r.Drain(ctx)

	// Both objects deleted.
	err := c.Get(ctx, client.ObjectKey{Name: "r0"}, &vpcv1alpha1.Relay{})
	require.True(t, apierrors.IsNotFound(err), "relay deleted")
	err = c.Get(ctx, client.ObjectKey{Namespace: DefaultLeaseNamespace, Name: LeaseName("r0")}, &apoxycoordv1.Lease{})
	require.True(t, apierrors.IsNotFound(err), "lease deleted")
}

func TestRelayRegistrarDrainMissingObjects(t *testing.T) {
	// Drain must be a safe no-op when the relay/lease are already gone.
	r, _ := newRegistrar(t, time.Unix(1_700_000_000, 0))
	require.NotPanics(t, func() { r.Drain(context.Background()) })
}
