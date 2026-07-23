package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

// tunnelWith builds a Tunnel with the given identity labels and addresses.
func tunnelWith(name, network, app string, addrs ...string) *vpcv1alpha1.Tunnel {
	return &vpcv1alpha1.Tunnel{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				vpcv1alpha1.LabelNetwork: network,
				"app":                    app,
			},
		},
		Spec:   vpcv1alpha1.TunnelSpec{NetworkRef: vpcv1alpha1.VPCNetworkRef{Name: network}},
		Status: vpcv1alpha1.TunnelStatus{Addresses: addrs},
	}
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

func TestVPCServiceReconcilerComputesEndpoints(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.VPCService{}).
		WithObjects(
			paymentsService(),
			tunnelWith("t-b", "corp", "payments", "fd61::b/96"),
			tunnelWith("t-a", "corp", "payments", "fd61::a/96", "100.64.0.1/32"),
			tunnelWith("t-other", "corp", "web", "fd61::c/96"),      // wrong selector
			tunnelWith("t-foreign", "other", "payments", "fd61::d/96"), // wrong network
		).
		Build()
	r := NewVPCServiceReconciler(c)

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "payments"}})
	require.NoError(t, err)

	var got vpcv1alpha1.VPCService
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "payments"}, &got))
	require.Len(t, got.Status.Endpoints, 2, "only in-network, selector-matching tunnels are members")
	// Deterministically sorted by TunnelRef.Name.
	require.Equal(t, "t-a", got.Status.Endpoints[0].TunnelRef.Name)
	require.Equal(t, []string{"fd61::a/96", "100.64.0.1/32"}, got.Status.Endpoints[0].Addresses)
	require.Equal(t, "t-b", got.Status.Endpoints[1].TunnelRef.Name)
}

func TestVPCServiceReconcilerTunnelMapping(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithObjects(paymentsService()).
		Build()
	r := NewVPCServiceReconciler(c)

	// A matching Tunnel enqueues its service.
	reqs := r.tunnelToServices(ctx, tunnelWith("t1", "corp", "payments", "fd61::1/96"))
	require.Len(t, reqs, 1)
	require.Equal(t, "payments", reqs[0].Name)

	// A non-matching Tunnel (wrong network) enqueues nothing.
	require.Empty(t, r.tunnelToServices(ctx, tunnelWith("t2", "other", "payments", "fd61::2/96")))
}
