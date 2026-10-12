package controllers

import (
	"context"
	"slices"
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

		wantEndpoints []string
		// wantAddrs are the member addresses. Nil skips the check.
		wantAddrs       []string
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
			// The Tunnel of an attachment has the attachment ID as its name and
			// the address of the agent in its /96.
			name: "attachment is an endpoint with the address of its agent",
			objects: []client.Object{
				corpNetwork(), paymentsService(),
				tunnelWith("0123456789abcdef0123456789abcdef", "corp", "payments", "fd61::b00:1/96"),
				tunnelWith("t-a", "corp", "payments", "fd61::a00:0/96", "100.64.0.1/32"),
				tunnelWith("fedcba9876543210fedcba9876543210", "corp", "web", "fd61::c00:1/96"), // wrong selector
			},
			wantEndpoints:   []string{"0123456789abcdef0123456789abcdef", "t-a"},
			wantAddrs:       []string{"fd61::b00:1", "fd61::a00:0", "100.64.0.1"},
			wantReady:       metav1.ConditionTrue,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonEndpointsAvailable,
			wantReconciled:  metav1.ConditionTrue,
		},
		{
			// The agent has one Tunnel for each relay connection, and all of
			// them have the address of the agent.
			name: "connections of one agent are one endpoint",
			objects: []client.Object{
				corpNetwork(), paymentsService(),
				tunnelWith("conn-2", "corp", "payments", "fd61::a00:1/96"),
				tunnelWith("conn-1", "corp", "payments", "fd61::a00:1/96"),
				tunnelWith("conn-3", "corp", "payments", "fd61::a00:1/96"),
				tunnelWith("other-agent", "corp", "payments", "fd61::b00:1/96"),
			},
			wantEndpoints:   []string{"conn-1", "other-agent"},
			wantAddrs:       []string{"fd61::a00:1", "fd61::b00:1"},
			wantReady:       metav1.ConditionTrue,
			wantReadyReason: vpcv1alpha1.VPCServiceReasonEndpointsAvailable,
			wantReconciled:  metav1.ConditionTrue,
		},
		{
			name: "connection with no terminating relay does not give the endpoint",
			objects: []client.Object{
				corpNetwork(), paymentsService(),
				relaylessTunnel(),
				tunnelWith("t-live", "corp", "payments", "fd61::f/96"),
			},
			wantEndpoints:   []string{"t-live"},
			wantAddrs:       []string{"fd61::f"},
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
			if tc.wantAddrs != nil {
				addrs, skipped := got.MemberAddrs()
				assert.Empty(t, skipped)
				gotAddrs := make([]string, len(addrs))
				for i, a := range addrs {
					gotAddrs[i] = a.String()
				}
				assert.Equal(t, tc.wantAddrs, gotAddrs)
			}

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

// The endpoints of Tunnels with one address set do not depend on the list
// order, and Tunnels with different address sets stay separate endpoints.
func TestMemberEndpoints(t *testing.T) {
	endpoint := func(name string, addrs ...string) vpcv1alpha1.VPCServiceEndpoint {
		return vpcv1alpha1.VPCServiceEndpoint{
			TunnelRef: vpcv1alpha1.TunnelRef{Name: name},
			Addresses: addrs,
		}
	}

	cases := []struct {
		name    string
		tunnels []*vpcv1alpha1.Tunnel

		want        []vpcv1alpha1.VPCServiceEndpoint
		wantPending int
	}{
		{
			name: "two Tunnels with one address give one endpoint",
			tunnels: []*vpcv1alpha1.Tunnel{
				tunnelWith("conn-1", "corp", "payments", "fd61::a00:1/96"),
				tunnelWith("conn-2", "corp", "payments", "fd61::a00:1/96"),
			},
			want: []vpcv1alpha1.VPCServiceEndpoint{endpoint("conn-1", "fd61::a00:1/96")},
		},
		{
			name: "two Tunnels with two addresses give two endpoints",
			tunnels: []*vpcv1alpha1.Tunnel{
				tunnelWith("conn-1", "corp", "payments", "fd61::a00:1/96"),
				tunnelWith("conn-2", "corp", "payments", "fd61::b00:1/96"),
			},
			want: []vpcv1alpha1.VPCServiceEndpoint{
				endpoint("conn-1", "fd61::a00:1/96"),
				endpoint("conn-2", "fd61::b00:1/96"),
			},
		},
		{
			// The endpoint keeps all addresses of its Tunnel, in the order of
			// the lowest Tunnel.
			name: "the same addresses in another order are one endpoint",
			tunnels: []*vpcv1alpha1.Tunnel{
				tunnelWith("conn-1", "corp", "payments", "fd61::a00:1/96", "100.64.0.1/32"),
				tunnelWith("conn-2", "corp", "payments", "100.64.0.1/32", "fd61::a00:1/96"),
			},
			want: []vpcv1alpha1.VPCServiceEndpoint{endpoint("conn-1", "fd61::a00:1/96", "100.64.0.1/32")},
		},
		{
			name: "a Tunnel that is not usable does not hide a usable one",
			tunnels: []*vpcv1alpha1.Tunnel{
				tunnelWith("conn-1", "corp", "payments"),
				tunnelWith("conn-2", "corp", "payments", "fd61::a00:1/96"),
			},
			want:        []vpcv1alpha1.VPCServiceEndpoint{endpoint("conn-2", "fd61::a00:1/96")},
			wantPending: 1,
		},
		{
			name: "no Tunnel gives an empty list",
			want: []vpcv1alpha1.VPCServiceEndpoint{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forward := make([]vpcv1alpha1.Tunnel, 0, len(tc.tunnels))
			for _, tunnel := range tc.tunnels {
				forward = append(forward, *tunnel)
			}
			reversed := slices.Clone(forward)
			slices.Reverse(reversed)

			for _, tunnels := range [][]vpcv1alpha1.Tunnel{forward, reversed} {
				got, pending := memberEndpoints(tunnels)
				assert.Equal(t, tc.want, got)
				assert.Equal(t, tc.wantPending, pending)
			}
		})
	}
}

// The endpoint of an agent with two connections stays while one of its Tunnels
// stays, and goes with the last one.
func TestVPCServiceReconcilerKeepsEndpointWhileOneConnectionStays(t *testing.T) {
	const addr = "fd61::a00:1/96"

	cases := []struct {
		name string
		// deleteFirst is the Tunnel that goes first; the other one goes second.
		deleteFirst, deleteSecond string
		// wantTunnelRef is the Tunnel of the endpoint after the first delete.
		wantTunnelRef string
		// wantWrite tells if the first delete changes the status.
		wantWrite bool
	}{
		{
			name:          "the Tunnel with the higher name goes first",
			deleteFirst:   "conn-2",
			deleteSecond:  "conn-1",
			wantTunnelRef: "conn-1",
		},
		{
			// The reference cannot stay on a Tunnel that is gone, so only the
			// reference moves.
			name:          "the Tunnel with the lower name goes first",
			deleteFirst:   "conn-1",
			deleteSecond:  "conn-2",
			wantTunnelRef: "conn-2",
			wantWrite:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := newVPCServiceClient(t, corpNetwork(), paymentsService(),
				tunnelWith("conn-1", "corp", "payments", addr),
				tunnelWith("conn-2", "corp", "payments", addr),
			)
			r := NewVPCServiceReconciler(c)
			req := reconcile.Request{NamespacedName: client.ObjectKey{Name: "payments"}}
			reconcileAndGet := func() vpcv1alpha1.VPCService {
				_, err := r.Reconcile(ctx, req)
				require.NoError(t, err)
				var got vpcv1alpha1.VPCService
				require.NoError(t, c.Get(ctx, req.NamespacedName, &got))
				return got
			}
			deleteTunnel := func(name string) {
				require.NoError(t, c.Delete(ctx, &vpcv1alpha1.Tunnel{ObjectMeta: metav1.ObjectMeta{Name: name}}))
			}

			before := reconcileAndGet()
			require.Len(t, before.Status.Endpoints, 1)
			assert.Equal(t, "conn-1", before.Status.Endpoints[0].TunnelRef.Name)
			assert.Equal(t, []string{addr}, before.Status.Endpoints[0].Addresses)

			deleteTunnel(tc.deleteFirst)
			after := reconcileAndGet()
			require.Len(t, after.Status.Endpoints, 1)
			assert.Equal(t, tc.wantTunnelRef, after.Status.Endpoints[0].TunnelRef.Name)
			assert.Equal(t, []string{addr}, after.Status.Endpoints[0].Addresses)
			assert.Equal(t, before.Status.Conditions, after.Status.Conditions)
			assert.Equal(t, tc.wantWrite, before.ResourceVersion != after.ResourceVersion)

			deleteTunnel(tc.deleteSecond)
			gone := reconcileAndGet()
			assert.Empty(t, gone.Status.Endpoints)
			assert.Equal(t, vpcv1alpha1.VPCServiceReasonNoEndpoints,
				condition(t, &gone, vpcv1alpha1.VPCServiceConditionReady).Reason)
		})
	}
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
