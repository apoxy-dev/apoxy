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
	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

// recordingRelay records the credential and egress calls the watcher makes.
type recordingRelay struct {
	stubRelay
	creds  map[string]string
	egress bool
}

func (r *recordingRelay) SetCredentials(network, token string) { r.creds[network] = token }
func (r *recordingRelay) SetEgressGateway(enabled bool)        { r.egress = enabled }

func TestVPCNetworkReconcilerFeedsCredentialsAndNetworkID(t *testing.T) {
	ctx := context.Background()

	network := &vpcv1alpha1.VPCNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec:       vpcv1alpha1.VPCNetworkSpec{EgressGateway: &vpcv1alpha1.EgressGatewaySpec{Enabled: true}},
		Status: vpcv1alpha1.VPCNetworkStatus{
			Credentials: &vpcv1alpha1.VPCNetworkCredentials{Token: "tok-1"},
			// /72 carrying NetworkID {0x00,0x00,0x01} in ULA bytes 6-8.
			OverlayCIDR: "fd61:706f:7879:0:100::/72",
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithObjects(network).
		Build()

	relay := &recordingRelay{stubRelay: stubRelay{name: "relay-0"}, creds: map[string]string{}}
	pub := NewTunnelPublisher(c, relay, ipalloc.NewLocalBlockLeaser(ctx), vni.NewVNIAllocator())
	r := NewVPCNetworkReconciler(c, relay, pub)

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "corp"}})
	require.NoError(t, err)

	require.Equal(t, "tok-1", relay.creds["corp"], "credential fed to the relay")
	require.True(t, relay.egress, "egress setting propagated")

	pub.mu.Lock()
	got, ok := pub.networks["corp"]
	pub.mu.Unlock()
	require.True(t, ok, "network resolved into the publisher")
	require.Equal(t, tunnet.NetworkID{0x00, 0x00, 0x01}, got)
}

func TestVPCNetworkReconcilerEgressIsDeterministicAcrossNetworks(t *testing.T) {
	ctx := context.Background()

	net := func(name string, egress bool) *vpcv1alpha1.VPCNetwork {
		return &vpcv1alpha1.VPCNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       vpcv1alpha1.VPCNetworkSpec{EgressGateway: &vpcv1alpha1.EgressGatewaySpec{Enabled: egress}},
		}
	}

	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithObjects(net("corp", true), net("guest", false)).
		Build()
	relay := &recordingRelay{stubRelay: stubRelay{name: "relay-0"}, creds: map[string]string{}}
	pub := NewTunnelPublisher(c, relay, ipalloc.NewLocalBlockLeaser(ctx), vni.NewVNIAllocator())
	r := NewVPCNetworkReconciler(c, relay, pub)

	reconcile := func(name string) {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: name}})
		require.NoError(t, err)
	}

	// A relay serving one egress-on and one egress-off network fails closed
	// regardless of reconcile order: egress stays off while any served network
	// does not want it.
	reconcile("corp")
	require.True(t, relay.egress, "sole egress-on network enables egress")
	reconcile("guest")
	require.False(t, relay.egress, "an egress-off network fails the global toggle closed")
	reconcile("corp") // Re-observing the egress-on network must not flip it back.
	require.False(t, relay.egress, "recompute is order-independent, not last-write-wins")

	// Deleting the egress-off network leaves only egress-on networks, so egress
	// re-enables.
	require.NoError(t, c.Delete(ctx, net("guest", false)))
	reconcile("guest")
	require.True(t, relay.egress, "removing the dissenting network re-enables egress")
}

func TestVPCNetworkReconcilerIgnoresMissing(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(publisherScheme(t)).Build()
	relay := &recordingRelay{stubRelay: stubRelay{name: "relay-0"}, creds: map[string]string{}}
	pub := NewTunnelPublisher(c, relay, ipalloc.NewLocalBlockLeaser(ctx), vni.NewVNIAllocator())
	r := NewVPCNetworkReconciler(c, relay, pub)

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "gone"}})
	require.NoError(t, err)
	require.Empty(t, relay.creds)
}
