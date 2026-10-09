package controllers

import (
	"context"
	"net/netip"
	"sync/atomic"
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

// writeCountClient counts the writes of Relay objects, and fails the first
// failUpdates updates.
type writeCountClient struct {
	client.Client
	creates, updates int
	failUpdates      int
}

func (c *writeCountClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*vpcv1alpha1.Relay); ok {
		c.creates++
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *writeCountClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*vpcv1alpha1.Relay); ok {
		c.updates++
		if c.failUpdates > 0 {
			c.failUpdates--
			return apierrors.NewServiceUnavailable("apiserver is down")
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

// TestRelayRegistrarEnsureRelay: the Relay object gets the addresses and the
// selector of the relay process, and an equal object gets no write.
func TestRelayRegistrarEnsureRelay(t *testing.T) {
	addrs := []string{"relay.example:6081", "1.2.3.4:6081"}
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"region": "west"}}
	object := func(addrs []string, sel *metav1.LabelSelector) *vpcv1alpha1.Relay {
		return &vpcv1alpha1.Relay{
			ObjectMeta: metav1.ObjectMeta{Name: "r0"},
			Spec:       vpcv1alpha1.RelaySpec{Addresses: addrs, NetworkSelector: sel},
			Status:     vpcv1alpha1.RelayStatus{Ready: true},
		}
	}
	cases := []struct {
		name     string
		existing *vpcv1alpha1.Relay
		// failUpdates is the number of updates that fail first.
		failUpdates int
		// calls is the number of ensureRelay calls. Only the last must pass.
		calls            int
		created          bool
		creates, updates int
	}{
		{name: "object absent", calls: 1, created: true, creates: 1},
		{name: "object equal", existing: object(addrs, selector), calls: 2},
		{name: "addresses differ", existing: object([]string{"dev:6081"}, selector), calls: 2, updates: 1},
		{name: "addresses in a different order", existing: object([]string{"1.2.3.4:6081", "relay.example:6081"}, selector), calls: 1, updates: 1},
		{name: "selector differs", existing: object(addrs, &metav1.LabelSelector{MatchLabels: map[string]string{"region": "east"}}), calls: 1, updates: 1},
		{name: "object has no selector", existing: object(addrs, nil), calls: 1, updates: 1},
		{name: "the write fails and the next call corrects it", existing: object([]string{"dev:6081"}, nil), failUpdates: 1, calls: 3, updates: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var objs []client.Object
			if tc.existing != nil {
				objs = append(objs, tc.existing)
			}
			_, base := newRegistrar(t, time.Unix(1_700_000_000, 0), objs...)
			c := &writeCountClient{Client: base, failUpdates: tc.failUpdates}
			r := NewRelayRegistrar(c, c, stubRelay{name: "r0"}, addrs, selector)

			var created bool
			var err error
			for i := range tc.calls {
				created, err = r.ensureRelay(ctx)
				if i < tc.failUpdates {
					require.Error(t, err)
					var got vpcv1alpha1.Relay
					require.NoError(t, base.Get(ctx, client.ObjectKey{Name: "r0"}, &got))
					require.Equal(t, tc.existing.Spec.Addresses, got.Spec.Addresses, "a write that failed changes nothing")
				}
			}
			require.NoError(t, err)
			require.Equal(t, tc.created, created)
			require.Equal(t, tc.creates, c.creates, "creates")
			require.Equal(t, tc.updates, c.updates, "updates")

			var got vpcv1alpha1.Relay
			require.NoError(t, base.Get(ctx, client.ObjectKey{Name: "r0"}, &got))
			require.Equal(t, addrs, got.Spec.Addresses)
			require.Equal(t, selector, got.Spec.NetworkSelector)
			if tc.existing != nil {
				require.True(t, got.Status.Ready, "an update keeps the status")
			}
		})
	}
}

func TestRelayRegistrarRenewLease(t *testing.T) {
	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0)

	t.Run("creates lease on first renew", func(t *testing.T) {
		r, c := newRegistrar(t, t0)
		created, err := r.renewLease(ctx)
		require.NoError(t, err)
		require.True(t, created)

		var lease apoxycoordv1.Lease
		require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: DefaultLeaseNamespace, Name: LeaseName("r0")}, &lease))
		require.NotNil(t, lease.Spec.RenewTime)
		require.Equal(t, t0.Unix(), lease.Spec.RenewTime.Unix())
		require.NotNil(t, lease.Spec.LeaseDurationSeconds)
		require.EqualValues(t, 40, *lease.Spec.LeaseDurationSeconds)
	})

	t.Run("bumps RenewTime on subsequent renew", func(t *testing.T) {
		r, c := newRegistrar(t, t0)
		_, err := r.renewLease(ctx)
		require.NoError(t, err)

		t1 := t0.Add(20 * time.Second)
		r.now = func() time.Time { return t1 }
		created, err := r.renewLease(ctx)
		require.NoError(t, err)
		require.False(t, created)

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

	created, err := r.renewLease(ctx)
	require.NoError(t, err)
	require.True(t, created, "a lease that the apiserver lost is created again")

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

// failingClient fails every call while fail is set.
type failingClient struct {
	client.Client
	fail *atomic.Bool
}

func (c failingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.fail.Load() {
		return apierrors.NewServiceUnavailable("apiserver is down")
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

// TestRelayRegistrarOnRenew: restored is set after each event that can lose the
// Tunnels, and not on a plain renewal.
func TestRelayRegistrarOnRenew(t *testing.T) {
	cases := []struct {
		name string
		// between runs after the first renewal.
		between func(t *testing.T, c client.Client, fail *atomic.Bool)
		want    bool
	}{
		{name: "plain renewal", between: func(*testing.T, client.Client, *atomic.Bool) {}},
		{
			name: "renewal after an outage",
			between: func(_ *testing.T, _ client.Client, fail *atomic.Bool) {
				fail.Store(true)
				time.Sleep(50 * time.Millisecond)
				fail.Store(false)
			},
			want: true,
		},
		{
			name: "relay lease deleted",
			between: func(t *testing.T, c client.Client, _ *atomic.Bool) {
				require.NoError(t, c.Delete(context.Background(), &apoxycoordv1.Lease{
					ObjectMeta: metav1.ObjectMeta{Namespace: DefaultLeaseNamespace, Name: LeaseName("r0")},
				}))
			},
			want: true,
		},
		{
			name: "relay object deleted",
			between: func(t *testing.T, c client.Client, _ *atomic.Bool) {
				require.NoError(t, c.Delete(context.Background(), &vpcv1alpha1.Relay{ObjectMeta: metav1.ObjectMeta{Name: "r0"}}))
			},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, base := newRegistrar(t, time.Unix(1_700_000_000, 0))
			fail := &atomic.Bool{}
			c := failingClient{Client: base, fail: fail}
			calls := make(chan bool, 100)
			r := NewRelayRegistrar(c, c, stubRelay{name: "r0"}, []string{"1.2.3.4:6081"}, nil,
				WithRenewInterval(10*time.Millisecond),
				WithOnRenew(func(restored bool) { calls <- restored }))
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- r.Start(ctx) }()
			defer func() {
				cancel()
				require.ErrorIs(t, <-done, context.Canceled)
			}()

			require.True(t, <-calls, "the first registration is restored")
			require.False(t, <-calls, "a renewal with no event is not restored")
			tc.between(t, base, fail)
			got := false
			for range 5 {
				got = got || <-calls
			}
			require.Equal(t, tc.want, got)
		})
	}
}

func TestRelayRegistrarSubSecondLeaseDuration(t *testing.T) {
	ctx := context.Background()
	r, c := newRegistrar(t, time.Unix(1_700_000_000, 0))
	r.leaseDuration = 500 * time.Millisecond
	_, err := r.renewLease(ctx)
	require.NoError(t, err)

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
