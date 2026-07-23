package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

// fakeConn is a controllers.Connection stub that records what the publisher
// assigns without touching a real router or icx handler.
type fakeConn struct {
	id            string
	network       string
	labels        map[string]string
	routes        []netip.Prefix
	agentInstance string

	overlay   string
	vniID     *uint
	addresses []string
	closed    bool
}

func (c *fakeConn) ID() string                            { return c.id }
func (c *fakeConn) Close() error                          { c.closed = true; return nil }
func (c *fakeConn) SetOverlayAddress(a string) error      { c.overlay = a; return nil }
func (c *fakeConn) SetVNI(_ context.Context, v uint) error { c.vniID = &v; return nil }
func (c *fakeConn) Stats() (ConnectionStats, bool)        { return ConnectionStats{}, false }
func (c *fakeConn) Network() string                       { return c.network }
func (c *fakeConn) Labels() map[string]string             { return c.labels }
func (c *fakeConn) AdvertisedRoutes() []netip.Prefix      { return c.routes }
func (c *fakeConn) AgentInstance() string                 { return c.agentInstance }
func (c *fakeConn) SetAddresses(a []string)               { c.addresses = a }
func (c *fakeConn) Addresses() []string                   { return c.addresses }

func publisherScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, vpcv1alpha1.Install(s))
	return s
}

// newPublisher builds a TunnelPublisher over a fake client + local leaser and
// resolves one network ("corp").
func newPublisher(t *testing.T) (*TunnelPublisher, client.Client, tunnet.NetworkID) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		Build()
	p := NewTunnelPublisher(c, stubRelay{name: "relay-0"}, ipalloc.NewLocalBlockLeaser(context.Background()), vni.NewVNIAllocator())
	netID := tunnet.NetworkID{0x00, 0x00, 0x01}
	p.SetNetworkID("corp", netID)
	return p, c, netID
}

func TestTunnelPublisherOnConnectCreatesTunnel(t *testing.T) {
	ctx := context.Background()
	p, c, _ := newPublisher(t)

	conn := &fakeConn{
		id:            "conn-a",
		network:       "corp",
		labels:        map[string]string{"app": "payments"},
		routes:        []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		agentInstance: "uuid-1",
	}
	require.NoError(t, p.OnConnect(ctx, "agent-a", "agent-a", conn))

	// The connection was assigned a VNI + primary overlay + dual-stack set.
	require.NotNil(t, conn.vniID)
	require.NotEmpty(t, conn.overlay)
	require.NotEmpty(t, conn.addresses)
	require.Equal(t, conn.overlay, conn.addresses[0], "primary address is the programmed overlay")

	var got vpcv1alpha1.Tunnel
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "conn-a"}, &got))
	require.Equal(t, "corp", got.Spec.NetworkRef.Name)
	require.Equal(t, "relay-0", got.Spec.RelayRef.Name)
	require.Equal(t, conn.addresses, got.Status.Addresses)
	require.Equal(t, []string{"10.20.0.0/16"}, got.Status.AdvertisedRoutes)

	// Identity labels stamped alongside the agent-declared label.
	require.Equal(t, "payments", got.Labels["app"])
	require.Equal(t, "corp", got.Labels[vpcv1alpha1.LabelNetwork])
	require.Equal(t, "agent-a", got.Labels[vpcv1alpha1.LabelTunnelName])
	require.Equal(t, "relay-0", got.Labels[LabelRelay])
	require.Equal(t, "uuid-1", got.Labels[vpcv1alpha1.LabelAgentInstance])
}

func TestTunnelPublisherOnDisconnectDeletesAndReleases(t *testing.T) {
	ctx := context.Background()
	p, c, _ := newPublisher(t)

	conn := &fakeConn{id: "conn-b", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-b", "agent-b", conn))
	firstOverlay := conn.overlay

	require.NoError(t, p.OnDisconnect(ctx, "agent-b", "conn-b"))

	err := c.Get(ctx, client.ObjectKey{Name: "conn-b"}, &vpcv1alpha1.Tunnel{})
	require.True(t, apierrors.IsNotFound(err), "Tunnel deleted on disconnect")

	// The released /96 is the lowest free slot, so the next connect reuses it.
	conn2 := &fakeConn{id: "conn-c", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-c", "agent-c", conn2))
	require.Equal(t, firstOverlay, conn2.overlay, "freed /96 is reused")
}

func TestTunnelPublisherOnDisconnectReleasesDespiteDeleteError(t *testing.T) {
	ctx := context.Background()

	// A client whose Tunnel Delete always fails: the disconnect must still return
	// the /96 + /32 + VNI to their pools, otherwise a transient apiserver error
	// permanently strands them (the conns record is already gone, nothing retries).
	failDelete := fmt.Errorf("apiserver unavailable")
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				return failDelete
			},
		}).
		Build()
	p := NewTunnelPublisher(c, stubRelay{name: "relay-0"}, ipalloc.NewLocalBlockLeaser(ctx), vni.NewVNIAllocator())
	p.SetNetworkID("corp", tunnet.NetworkID{0x00, 0x00, 0x01})

	conn := &fakeConn{id: "conn-d", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-d", "agent-d", conn))
	firstOverlay := conn.overlay

	err := p.OnDisconnect(ctx, "agent-d", "conn-d")
	require.ErrorIs(t, err, failDelete, "delete error is surfaced")

	// Despite the delete error the /96 was released: the next connect reuses it.
	conn2 := &fakeConn{id: "conn-e", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-e", "agent-e", conn2))
	require.Equal(t, firstOverlay, conn2.overlay, "address released despite Tunnel delete failure")
}

func TestTunnelPublisherOnConnectUnresolvedNetwork(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPublisher(t)

	conn := &fakeConn{id: "conn-x", network: "unknown"}
	err := p.OnConnect(ctx, "agent-x", "agent-x", conn)
	require.Error(t, err, "connect to an unprovisioned network fails")
	require.Nil(t, conn.vniID, "nothing assigned when the network is unresolved")
}

func TestTunnelPublisherOnDisconnectOrphan(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPublisher(t)
	// No allocation record and no Tunnel object: disconnect is a safe no-op.
	require.NoError(t, p.OnDisconnect(ctx, "agent-z", "conn-z"))
}
