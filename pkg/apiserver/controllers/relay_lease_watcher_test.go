package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apoxycoordv1 "github.com/apoxy-dev/apoxy/api/coordination/v1"
	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	tunnelctrl "github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
)

func watcherScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, vpcv1alpha1.Install(s))
	require.NoError(t, apoxycoordv1.Install(s))
	return s
}

func relayLease(renewAgo time.Duration, now time.Time) *apoxycoordv1.Lease {
	renew := metav1.NewMicroTime(now.Add(-renewAgo))
	return &apoxycoordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: tunnelctrl.LeaseName("r0")},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptr.To("r0"),
			LeaseDurationSeconds: ptr.To(int32(40)),
			RenewTime:            &renew,
		},
	}
}

func relayObj(ready bool) *vpcv1alpha1.Relay {
	return &vpcv1alpha1.Relay{
		ObjectMeta: metav1.ObjectMeta{Name: "r0"},
		Status:     vpcv1alpha1.RelayStatus{Ready: ready},
	}
}

func leaseReq() reconcile.Request {
	return reconcile.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: tunnelctrl.LeaseName("r0")}}
}

func TestRelayLeaseWatcherReadinessTransitions(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	cases := []struct {
		name       string
		renewAgo   time.Duration
		startReady bool
		wantReady  bool
		wantWrite  bool // whether Status was expected to change
	}{
		{name: "fresh lease flips not-ready to ready", renewAgo: 5 * time.Second, startReady: false, wantReady: true, wantWrite: true},
		{name: "stale lease flips ready to not-ready", renewAgo: 90 * time.Second, startReady: true, wantReady: false, wantWrite: true},
		{name: "fresh lease already ready is a no-op", renewAgo: 5 * time.Second, startReady: true, wantReady: true, wantWrite: false},
		{name: "stale lease already not-ready is a no-op", renewAgo: 90 * time.Second, startReady: false, wantReady: false, wantWrite: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lease := relayLease(tc.renewAgo, now)
			relay := relayObj(tc.startReady)
			c := fake.NewClientBuilder().
				WithScheme(watcherScheme(t)).
				WithStatusSubresource(&vpcv1alpha1.Relay{}).
				WithObjects(lease, relay).
				Build()
			w := NewRelayLeaseWatcher(c)
			w.now = func() time.Time { return now }

			var before vpcv1alpha1.Relay
			require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "r0"}, &before))

			_, err := w.Reconcile(ctx, leaseReq())
			require.NoError(t, err)

			var after vpcv1alpha1.Relay
			require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "r0"}, &after))
			require.Equal(t, tc.wantReady, after.Status.Ready)

			if tc.wantWrite {
				require.NotEqual(t, before.ResourceVersion, after.ResourceVersion, "expected a status write")
			} else {
				require.Equal(t, before.ResourceVersion, after.ResourceVersion, "no write expected")
			}
		})
	}
}

// relayTunnel returns a Tunnel of relay r0.
func relayTunnel(name string) *vpcv1alpha1.Tunnel {
	return &vpcv1alpha1.Tunnel{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{tunnelctrl.LabelRelay: "r0"},
		},
	}
}

func TestRelayLeaseWatcherGCsRelayWhenLeaseGone(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Relay{}).
		WithObjects(relayObj(true), relayTunnel("conn-1")).
		Build()
	w := NewRelayLeaseWatcher(c)

	_, err := w.Reconcile(ctx, leaseReq())
	require.NoError(t, err)

	err = c.Get(ctx, client.ObjectKey{Name: "r0"}, &vpcv1alpha1.Relay{})
	require.True(t, apierrors.IsNotFound(err), "relay deleted")
	err = c.Get(ctx, client.ObjectKey{Name: "conn-1"}, &vpcv1alpha1.Tunnel{})
	require.True(t, apierrors.IsNotFound(err), "tunnel deleted")
}

func TestRelayLeaseWatcherIgnoresForeignLease(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(watcherScheme(t)).Build()
	w := NewRelayLeaseWatcher(c)

	res, err := w.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "leader-election-x"},
	})
	require.NoError(t, err)
	require.Zero(t, res.RequeueAfter)
}

func TestRelayLeaseWatcherRequeuesLiveLease(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Relay{}).
		WithObjects(relayLease(5*time.Second, now), relayObj(true)).
		Build()
	w := NewRelayLeaseWatcher(c)
	w.now = func() time.Time { return now }

	res, err := w.Reconcile(ctx, leaseReq())
	require.NoError(t, err)
	require.Equal(t, w.checkInterval, res.RequeueAfter, "live lease is re-checked")
}

func TestRelayLeaseWatcherKeepsExpiredWithinGrace(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	// 70s is past the 40s lease and inside the 60s grace.
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Relay{}).
		WithObjects(relayLease(70*time.Second, now), relayObj(true)).
		Build()
	w := NewRelayLeaseWatcher(c)
	w.now = func() time.Time { return now }

	res, err := w.Reconcile(ctx, leaseReq())
	require.NoError(t, err)
	require.Equal(t, w.checkInterval, res.RequeueAfter, "checked again")

	var relay vpcv1alpha1.Relay
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "r0"}, &relay), "relay kept during grace")
	require.False(t, relay.Status.Ready, "marked not-ready during grace")
}

func TestRelayLeaseWatcherGCsAfterGrace(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	// 120s is past the 40s lease and the 60s grace.
	slotTunnel := relayTunnel("conn-slot")
	slotTunnel.Labels[ipalloc.LabelSlot] = "000002-0100"
	slotTunnel.Labels[ipalloc.LabelSlotGeneration] = "1"
	otherRelay := relayTunnel("conn-other")
	otherRelay.Labels[tunnelctrl.LabelRelay] = "r1"
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Relay{}).
		WithObjects(relayLease(120*time.Second, now), relayObj(true), relayTunnel("conn-1"), slotTunnel, otherRelay).
		Build()
	w := NewRelayLeaseWatcher(c)
	w.now = func() time.Time { return now }

	res, err := w.Reconcile(ctx, leaseReq())
	require.NoError(t, err)
	require.Zero(t, res.RequeueAfter, "no requeue")

	err = c.Get(ctx, client.ObjectKey{Name: "r0"}, &vpcv1alpha1.Relay{})
	require.True(t, apierrors.IsNotFound(err), "relay deleted")
	err = c.Get(ctx, client.ObjectKey{Namespace: "default", Name: tunnelctrl.LeaseName("r0")}, &apoxycoordv1.Lease{})
	require.True(t, apierrors.IsNotFound(err), "lease deleted")
	err = c.Get(ctx, client.ObjectKey{Name: "conn-1"}, &vpcv1alpha1.Tunnel{})
	require.True(t, apierrors.IsNotFound(err), "tunnel deleted")
	err = c.Get(ctx, client.ObjectKey{Name: "conn-slot"}, &vpcv1alpha1.Tunnel{})
	require.True(t, apierrors.IsNotFound(err), "slot-owned tunnel deleted")
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "conn-other"}, &vpcv1alpha1.Tunnel{}), "other relay's tunnel kept")
}

func TestRelayLeaseWatcherIgnoresOtherNamespace(t *testing.T) {
	ctx := context.Background()
	// A relay lease in another namespace must not touch the Relay of that name.
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Relay{}).
		WithObjects(relayObj(true)).
		Build()
	w := NewRelayLeaseWatcher(c)

	res, err := w.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "other", Name: tunnelctrl.LeaseName("r0")},
	})
	require.NoError(t, err)
	require.Zero(t, res.RequeueAfter)
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "r0"}, &vpcv1alpha1.Relay{}), "relay untouched")
}
