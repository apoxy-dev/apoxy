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

	// setAddrsErr, when set, decides each SetAddresses call, so a test can
	// reject one address family the way a failed route add does.
	setAddrsErr func([]string) error

	overlay   string
	vniID     *uint
	addresses []string
	setAddrs  [][]string
	closed    bool
}

func (c *fakeConn) ID() string                             { return c.id }
func (c *fakeConn) Close() error                           { c.closed = true; return nil }
func (c *fakeConn) SetOverlayAddress(a string) error       { c.overlay = a; return nil }
func (c *fakeConn) SetVNI(_ context.Context, v uint) error { c.vniID = &v; return nil }
func (c *fakeConn) Stats() (ConnectionStats, bool)         { return ConnectionStats{}, false }
func (c *fakeConn) Network() string                        { return c.network }
func (c *fakeConn) Scope() string                          { return "" }
func (c *fakeConn) Labels() map[string]string              { return c.labels }
func (c *fakeConn) AdvertisedRoutes() []netip.Prefix       { return c.routes }
func (c *fakeConn) AgentInstance() string                  { return c.agentInstance }
func (c *fakeConn) Addresses() []string                    { return c.addresses }

func (c *fakeConn) SetAddresses(a []string) error {
	c.setAddrs = append(c.setAddrs, a)
	if c.setAddrsErr != nil {
		if err := c.setAddrsErr(a); err != nil {
			return err
		}
	}
	c.addresses = a
	return nil
}

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
	p := NewTunnelPublisher(c, stubRelay{name: "relay-0"}, ipalloc.NewLocalSlotLeaser(), vni.NewVNIAllocator())
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

// TestTunnelPublisherOnConnectV4Failure pins the §2.4 best-effort contract at
// the connect path: the /32 is egress-only, so a connection that cannot carry
// it comes up v6-only instead of being refused.
func TestTunnelPublisherOnConnectV4Failure(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		failOn     func([]string) error
		wantErr    bool
		wantV4     bool
		wantTunnel bool
	}{
		{
			name: "v4 route rejected degrades to v6-only",
			failOn: func(a []string) error {
				if len(a) > 1 {
					return fmt.Errorf("router.AddRoute(%s) failed: file exists", a[1])
				}
				return nil
			},
			wantV4:     false,
			wantTunnel: true,
		},
		{
			name:       "a failure that outlives the /32 still refuses the connect",
			failOn:     func([]string) error { return fmt.Errorf("virtual network gone") },
			wantErr:    true,
			wantTunnel: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, c, _ := newPublisher(t)
			conn := &fakeConn{id: "conn-v4", network: "corp", setAddrsErr: tc.failOn}

			err := p.OnConnect(ctx, "agent-v4", "agent-v4", conn)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, conn.addresses)
				require.Equal(t, conn.overlay, conn.addresses[0])
				require.Len(t, conn.addresses, 1, "the connection kept only its /96")
				require.Len(t, conn.setAddrs, 2, "the /32 was attempted, then dropped")
			}

			gotErr := c.Get(ctx, client.ObjectKey{Name: "conn-v4"}, &vpcv1alpha1.Tunnel{})
			require.Equal(t, tc.wantTunnel, gotErr == nil, "Tunnel presence")

			// Either way the /32 went back: the next connection is handed one.
			next := &fakeConn{id: "conn-next", network: "corp"}
			require.NoError(t, p.OnConnect(ctx, "agent-next", "agent-next", next))
			require.Len(t, next.addresses, 2, "the dropped /32 was returned to the slot")
		})
	}
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
	p := NewTunnelPublisher(c, stubRelay{name: "relay-0"}, ipalloc.NewLocalSlotLeaser(), vni.NewVNIAllocator())
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

// TestLabelValue asserts the agent-instance sanitizer: valid values pass
// through, over-long clean values are truncated to the same 32-char prefix
// current agents derive at the source (so labels stay greppable against the
// raw metric label / container ID during version skew), and only otherwise
// invalid values are hashed.
func TestLabelValue(t *testing.T) {
	fullHex := "bf3df5c6a1e2d3c4b5a6978877665544bf3df5c6a1e2d3c4b5a6978877665544" // 64 hex, like a CRI container ID
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "valid passes through", in: "abc-123", want: "abc-123"},
		{name: "empty passes through", in: "", want: ""},
		{name: "over-long clean value truncates to the producer prefix", in: fullHex, want: fullHex[:32]},
		{name: "invalid characters hash", in: "not/a/label!", want: labelValue("not/a/label!")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := labelValue(tc.in)
			require.Equal(t, tc.want, got)
			require.LessOrEqual(t, len(got), 63)
		})
	}
	// The hashed form is stable and distinct from the input.
	h := labelValue("not/a/label!")
	require.Equal(t, h, labelValue("not/a/label!"))
	require.Len(t, h, 32)
	require.NotContains(t, h, "/")
}

// TestTunnelPublisherSharedV4Pool covers the multi-tenant relay shape: one
// publisher per tenant, every publisher on the same relay and so on the same
// route table. Slot ids restart at the floor for each network, so two tenants'
// first connections only get different /32s if the shared leaser hands their
// slots disjoint /24s.
func TestTunnelPublisherSharedV4Pool(t *testing.T) {
	ctx := context.Background()
	leaser := ipalloc.NewLocalSlotLeaser()

	connect := func(netID tunnet.NetworkID, id string) (v6, v4 netip.Prefix) {
		c := fake.NewClientBuilder().
			WithScheme(publisherScheme(t)).
			WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
			Build()
		p := NewTunnelPublisher(c, stubRelay{name: "relay-0"}, leaser, vni.NewVNIAllocator())
		p.SetNetworkID("corp", netID)
		conn := &fakeConn{id: id, network: "corp"}
		require.NoError(t, p.OnConnect(ctx, id, id, conn))
		require.Len(t, conn.addresses, 2, "connect must carry both families")
		return netip.MustParsePrefix(conn.addresses[0]), netip.MustParsePrefix(conn.addresses[1])
	}

	v6a, v4a := connect(tunnet.NetworkID{0x00, 0x00, 0x01}, "conn-tenant-a")
	v6b, v4b := connect(tunnet.NetworkID{0x00, 0x00, 0x02}, "conn-tenant-b")

	slotOf := func(p netip.Prefix) uint16 {
		b := p.Addr().As16()
		return uint16(b[9])<<8 | uint16(b[10])
	}
	require.Equal(t, slotOf(v6a), slotOf(v6b),
		"precondition: both tenants must hold the same slot id for this to test anything")
	require.NotEqual(t, v4a.Addr(), v4b.Addr(), "two tenants were handed the same /32")
}
