package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

// tunnelWith builds a live Tunnel: relay-terminated, with the given identity
// labels and overlay addresses.
func tunnelWith(name, network, app string, addrs ...string) *vpcv1alpha1.Tunnel {
	return &vpcv1alpha1.Tunnel{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				vpcv1alpha1.LabelNetwork: network,
				"app":                    app,
			},
		},
		Spec: vpcv1alpha1.TunnelSpec{
			NetworkRef: vpcv1alpha1.VPCNetworkRef{Name: network},
			RelayRef:   vpcv1alpha1.RelayRef{Name: "relay-0"},
		},
		Status: vpcv1alpha1.TunnelStatus{Addresses: addrs},
	}
}

func corpNetwork() *vpcv1alpha1.VPCNetwork {
	return &vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}}
}

func paymentsService() *vpcv1alpha1.VPCService {
	return &vpcv1alpha1.VPCService{
		ObjectMeta: metav1.ObjectMeta{Name: "payments"},
		Spec: vpcv1alpha1.VPCServiceSpec{
			NetworkRef: vpcv1alpha1.VPCNetworkRef{Name: "corp"},
			Selector:   &metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}},
		},
	}
}

// condition returns the named condition, failing the test if it is absent.
func condition(t *testing.T, svc *vpcv1alpha1.VPCService, typ string) *metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(svc.Status.Conditions, typ)
	require.NotNil(t, c, "%s condition not set", typ)
	return c
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// newVPCServiceClient builds a fake client carrying the same network index the
// manager registers in SetupWithManager, so the watch mappings are exercised
// through the lookup they actually use in production.
func newVPCServiceClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.VPCService{}).
		WithIndex(&vpcv1alpha1.VPCService{}, IndexServiceNetwork, func(obj client.Object) []string {
			svc, ok := obj.(*vpcv1alpha1.VPCService)
			if !ok || svc.Spec.NetworkRef.Name == "" {
				return nil
			}
			return []string{svc.Spec.NetworkRef.Name}
		}).
		WithObjects(objs...).
		Build()
}

func TestVPCServiceReconciler(t *testing.T) {
	// noSelector and emptySelector are the two shapes the API now rejects at
	// admission but that objects stored before that rule can still have. The
	// empty one is the dangerous half: LabelSelectorAsSelector turns it into
	// labels.Everything(), so treating it as valid would publish every Tunnel
	// in the network as a member of this service.
	noSelector := func() *vpcv1alpha1.VPCService {
		s := paymentsService()
		s.Spec.Selector = nil
		return s
	}
	emptySelector := func() *vpcv1alpha1.VPCService {
		s := paymentsService()
		s.Spec.Selector = &metav1.LabelSelector{}
		return s
	}
	// addresslessTunnel covers both the window between the relay's Tunnel
	// create and its status write, and a hand-authored Tunnel that never
	// gets addresses at all.
	addresslessTunnel := func() *vpcv1alpha1.Tunnel {
		return tunnelWith("t-pending", "corp", "payments")
	}
	relaylessTunnel := func() *vpcv1alpha1.Tunnel {
		t := tunnelWith("t-forged", "corp", "payments", "fd61::f/96")
		t.Spec.RelayRef.Name = ""
		return t
	}

	cases := []struct {
		name    string
		objects []client.Object

		wantEndpoints   []string
		wantReady       metav1.ConditionStatus
		wantReadyReason string
		wantReconciled  metav1.ConditionStatus
	}{
		{
			name: "live members become endpoints",
			objects: []client.Object{
				corpNetwork(), paymentsService(),
				tunnelWith("t-b", "corp", "payments", "fd61::b/96"),
				tunnelWith("t-a", "corp", "payments", "fd61::a/96", "100.64.0.1/32"),
				tunnelWith("t-other", "corp", "web", "fd61::c/96"),         // wrong selector
				tunnelWith("t-foreign", "other", "payments", "fd61::d/96"), // wrong network
			},
			wantEndpoints:   []string{"t-a", "t-b"},
			wantReady:       metav1.ConditionTrue,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonEndpointsAvailable,
			wantReconciled:  metav1.ConditionTrue,
		},
		{
			name:    "no matching member is reconciled but not ready",
			objects: []client.Object{corpNetwork(), paymentsService()},
			// Computing an empty endpoint list is not service readiness.
			wantEndpoints:   nil,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonNoEndpoints,
			wantReconciled:  metav1.ConditionTrue,
		},
		{
			name:            "member with no overlay address is not an endpoint",
			objects:         []client.Object{corpNetwork(), paymentsService(), addresslessTunnel()},
			wantEndpoints:   nil,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonNoEndpoints,
			wantReconciled:  metav1.ConditionTrue,
		},
		{
			name:            "member with no terminating relay is not an endpoint",
			objects:         []client.Object{corpNetwork(), paymentsService(), relaylessTunnel()},
			wantEndpoints:   nil,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonNoEndpoints,
			wantReconciled:  metav1.ConditionTrue,
		},
		{
			name: "unusable members are dropped, usable ones kept",
			objects: []client.Object{
				corpNetwork(), paymentsService(),
				addresslessTunnel(),
				tunnelWith("t-a", "corp", "payments", "fd61::a/96"),
			},
			wantEndpoints:   []string{"t-a"},
			wantReady:       metav1.ConditionTrue,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonEndpointsAvailable,
			wantReconciled:  metav1.ConditionTrue,
		},
		{
			// Endpoints stay whatever they were — here, nothing. See
			// TestVPCServiceReconcilerKeepsEndpointsWhenNetworkDeleted for
			// the case that has members to preserve.
			name: "dangling network reference is neither reconciled nor ready",
			objects: []client.Object{
				paymentsService(),
				tunnelWith("t-a", "corp", "payments", "fd61::a/96"),
			},
			wantEndpoints:   nil,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonNetworkNotFound,
			wantReconciled:  metav1.ConditionFalse,
		},
		{
			name: "missing selector is neither reconciled nor ready",
			objects: []client.Object{
				corpNetwork(), noSelector(),
				tunnelWith("t-a", "corp", "payments", "fd61::a/96"),
			},
			wantEndpoints:   nil,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonInvalidSelector,
			wantReconciled:  metav1.ConditionFalse,
		},
		{
			// The empty selector must NOT be read as "every Tunnel in the
			// network": that would publish unrelated members under this
			// service's name and report it Ready while doing so.
			name: "empty selector does not select the whole network",
			objects: []client.Object{
				corpNetwork(), emptySelector(),
				tunnelWith("t-a", "corp", "payments", "fd61::a/96"),
				tunnelWith("t-unrelated", "corp", "web", "fd61::c/96"),
			},
			wantEndpoints:   nil,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonInvalidSelector,
			wantReconciled:  metav1.ConditionFalse,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := newVPCServiceClient(t, tc.objects...)
			r := NewVPCServiceReconciler(c)

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "payments"}})
			require.NoError(t, err)

			var got vpcv1alpha1.VPCService
			require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "payments"}, &got))

			names := make([]string, 0, len(got.Status.Endpoints))
			for _, ep := range got.Status.Endpoints {
				names = append(names, ep.TunnelRef.Name)
			}
			// Deterministically sorted by TunnelRef.Name.
			assert.Equal(t, tc.wantEndpoints, nilIfEmpty(names))

			ready := condition(t, &got, vpcv1alpha1.VPCServiceConditionReady)
			assert.Equal(t, tc.wantReady, ready.Status)
			assert.Equal(t, tc.wantReadyReason, ready.Reason)

			reconciled := condition(t, &got, vpcv1alpha1.VPCServiceConditionReconciled)
			assert.Equal(t, tc.wantReconciled, reconciled.Status)
		})
	}
}

// A kept member's recorded addresses survive intact: the usability filter
// drops members, it does not rewrite what a kept one publishes.
func TestVPCServiceReconcilerKeepsMemberAddresses(t *testing.T) {
	ctx := context.Background()
	c := newVPCServiceClient(t, corpNetwork(), paymentsService(),
		tunnelWith("t-a", "corp", "payments", "fd61::a/96", "100.64.0.1/32"),
	)

	_, err := NewVPCServiceReconciler(c).Reconcile(ctx,
		reconcile.Request{NamespacedName: client.ObjectKey{Name: "payments"}})
	require.NoError(t, err)

	var got vpcv1alpha1.VPCService
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "payments"}, &got))
	require.Len(t, got.Status.Endpoints, 1)
	assert.Equal(t, []string{"fd61::a/96", "100.64.0.1/32"}, got.Status.Endpoints[0].Addresses)
}

// Deleting a VPCNetwork does not disconnect its Tunnels, so the members it
// scoped are still carrying traffic. The service must report the problem in
// its conditions without dropping the endpoints both DNS planes publish
// straight off — otherwise a control-plane bookkeeping change blackholes live
// requests.
func TestVPCServiceReconcilerKeepsEndpointsWhenNetworkDeleted(t *testing.T) {
	ctx := context.Background()
	svc := paymentsService()
	svc.Status.Endpoints = []vpcv1alpha1.VPCServiceEndpoint{
		{TunnelRef: vpcv1alpha1.TunnelRef{Name: "t-a"}, Addresses: []string{"fd61::a/96"}},
	}
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.VPCService{}).
		// No corpNetwork(): the network was deleted out from under the service.
		WithObjects(svc, tunnelWith("t-a", "corp", "payments", "fd61::a/96")).
		Build()

	_, err := NewVPCServiceReconciler(c).Reconcile(ctx,
		reconcile.Request{NamespacedName: client.ObjectKey{Name: "payments"}})
	require.NoError(t, err)

	var got vpcv1alpha1.VPCService
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "payments"}, &got))
	require.Len(t, got.Status.Endpoints, 1, "live members must survive the network's deletion")
	assert.Equal(t, "t-a", got.Status.Endpoints[0].TunnelRef.Name)

	ready := condition(t, &got, vpcv1alpha1.VPCServiceConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, vpcv1alpha1.VPCServiceReasonNetworkNotFound, ready.Reason)
}

// An unusable selector is the opposite case: the previous endpoint list was
// derived from a rule that cannot be trusted, so it is cleared rather than
// preserved.
func TestVPCServiceReconcilerClearsEndpointsOnUnusableSelector(t *testing.T) {
	ctx := context.Background()
	svc := paymentsService()
	svc.Spec.Selector = &metav1.LabelSelector{}
	svc.Status.Endpoints = []vpcv1alpha1.VPCServiceEndpoint{
		{TunnelRef: vpcv1alpha1.TunnelRef{Name: "t-unrelated"}, Addresses: []string{"fd61::c/96"}},
	}
	c := newVPCServiceClient(t, corpNetwork(), svc)

	_, err := NewVPCServiceReconciler(c).Reconcile(ctx,
		reconcile.Request{NamespacedName: client.ObjectKey{Name: "payments"}})
	require.NoError(t, err)

	var got vpcv1alpha1.VPCService
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "payments"}, &got))
	assert.Empty(t, got.Status.Endpoints, "members from a degenerate selector must not keep being published")
	assert.Equal(t, vpcv1alpha1.VPCServiceReasonInvalidSelector,
		condition(t, &got, vpcv1alpha1.VPCServiceConditionReady).Reason)
}

// A service that loses its last member goes back to not-Ready instead of
// carrying a stale Ready=True from the pass that had endpoints.
func TestVPCServiceReconcilerClearsReadyOnLastMemberLoss(t *testing.T) {
	ctx := context.Background()
	tunnel := tunnelWith("t-a", "corp", "payments", "fd61::a/96")
	c := newVPCServiceClient(t, corpNetwork(), paymentsService(), tunnel)
	r := NewVPCServiceReconciler(c)
	req := reconcile.Request{NamespacedName: client.ObjectKey{Name: "payments"}}

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)
	var got vpcv1alpha1.VPCService
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "payments"}, &got))
	require.Equal(t, metav1.ConditionTrue, condition(t, &got, vpcv1alpha1.VPCServiceConditionReady).Status)

	require.NoError(t, c.Delete(ctx, tunnel))
	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err)
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "payments"}, &got))

	assert.Empty(t, got.Status.Endpoints)
	ready := condition(t, &got, vpcv1alpha1.VPCServiceConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, vpcv1alpha1.VPCServiceReasonNoEndpoints, ready.Reason)
	assert.Equal(t, metav1.ConditionTrue, condition(t, &got, vpcv1alpha1.VPCServiceConditionReconciled).Status)
}

func TestVPCServiceReconcilerTunnelMapping(t *testing.T) {
	ctx := context.Background()
	c := newVPCServiceClient(t, paymentsService())
	r := NewVPCServiceReconciler(c)

	// A matching Tunnel enqueues its service.
	reqs := r.tunnelToServices(ctx, tunnelWith("t1", "corp", "payments", "fd61::1/96"))
	require.Len(t, reqs, 1)
	require.Equal(t, "payments", reqs[0].Name)

	// A non-matching Tunnel (wrong network) enqueues nothing.
	require.Empty(t, r.tunnelToServices(ctx, tunnelWith("t2", "other", "payments", "fd61::2/96")))
}

func TestVPCServiceReconcilerNetworkMapping(t *testing.T) {
	ctx := context.Background()
	c := newVPCServiceClient(t, paymentsService())
	r := NewVPCServiceReconciler(c)

	// The owning network enqueues its services, so its delete re-evaluates them.
	reqs := r.networkToServices(ctx, corpNetwork())
	require.Len(t, reqs, 1)
	require.Equal(t, "payments", reqs[0].Name)

	other := &vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "other"}}
	require.Empty(t, r.networkToServices(ctx, other))
}
