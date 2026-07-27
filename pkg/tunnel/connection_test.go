package tunnel

import (
	"context"
	"net/netip"
	"testing"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	conntypes "github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

// recordingRouter records address/route programming so tests can assert what
// the connection installed on the relay's router.
type recordingRouter struct {
	addAddrs  []netip.Prefix
	delAddrs  []netip.Prefix
	addRoutes []netip.Prefix
	delRoutes []netip.Prefix
}

func (r *recordingRouter) Start(context.Context) error { return nil }
func (r *recordingRouter) AddAddr(p netip.Prefix, _ conntypes.Connection) error {
	r.addAddrs = append(r.addAddrs, p)
	return nil
}
func (r *recordingRouter) DelAddr(p netip.Prefix) error {
	r.delAddrs = append(r.delAddrs, p)
	return nil
}
func (r *recordingRouter) AddRoute(p netip.Prefix) error {
	r.addRoutes = append(r.addRoutes, p)
	return nil
}
func (r *recordingRouter) DelRoute(p netip.Prefix) error {
	r.delRoutes = append(r.delRoutes, p)
	return nil
}
func (r *recordingRouter) Close() error { return nil }

func countPrefix(ps []netip.Prefix, want netip.Prefix) int {
	n := 0
	for _, p := range ps {
		if p == want {
			n++
		}
	}
	return n
}

// TestConnectionDualStackProgramming asserts that SetAddresses programs the
// IPv4 /32 alongside the primary IPv6 prefix: onto the router (netstack
// address + SNAT in production) and into the VNI's allowed routes (without
// which the icx RX check drops every IPv4 packet as an invalid inner source).
func TestConnectionDualStackProgramming(t *testing.T) {
	const vni = uint(77)
	v6 := netip.MustParsePrefix("fd00:cafe::2/96")
	v4 := netip.MustParsePrefix("10.1.2.3/32")

	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)

	rtr := &recordingRouter{}
	conn := &connection{
		id:         "conn-dual-stack",
		handler:    h,
		router:     rtr,
		localAddr:  netip.MustParseAddrPort("127.0.0.1:6081"),
		remoteAddr: netip.MustParseAddrPort("127.0.0.1:7081"),
	}

	// Mirror TunnelPublisher.OnConnect ordering: primary address, VNI, then the
	// full dual-stack set.
	require.NoError(t, conn.SetOverlayAddress(v6.String()))
	require.NoError(t, conn.SetVNI(context.Background(), vni))
	require.NoError(t, conn.SetAddresses([]string{v6.String(), v4.String()}))

	vnet, ok := h.GetVirtualNetwork(vni)
	require.True(t, ok)

	routes := vnet.AllowedRoutes()
	hasRoute := func(src, dst netip.Prefix) bool {
		for _, r := range routes {
			if r.Src == src && r.Dst == dst {
				return true
			}
		}
		return false
	}
	require.True(t, hasRoute(netip.MustParsePrefix("::/0"), v6),
		"IPv6 allowed route must be installed")
	require.True(t, hasRoute(netip.MustParsePrefix("0.0.0.0/0"), v4),
		"IPv4 allowed route must be installed — without it the relay drops all v4 at the RX check")

	require.Equal(t, 1, countPrefix(rtr.addAddrs, v4), "v4 /32 must be claimed on the router once")
	require.Equal(t, []string{v6.String(), v4.String()}, conn.Addresses(),
		"reported addresses derive from programmed state, primary first")

	// A repeat SetAddresses is idempotent: no duplicate router programming.
	require.NoError(t, conn.SetAddresses([]string{v6.String(), v4.String()}))
	require.Equal(t, 1, countPrefix(rtr.addAddrs, v4))

	// Rejects garbage without partial state.
	require.Error(t, conn.SetAddresses([]string{"not-a-prefix"}))
	require.Equal(t, []string{v6.String(), v4.String()}, conn.Addresses())

	// Reconcile: dropping the v4 from the set unprograms it and removes its
	// allowed route, so a revoked prefix stops passing the RX check.
	require.NoError(t, conn.SetAddresses([]string{v6.String()}))
	require.Equal(t, 1, countPrefix(rtr.delAddrs, v4), "revoked v4 /32 must be unprogrammed")
	vnet, ok = h.GetVirtualNetwork(vni)
	require.True(t, ok)
	routes = vnet.AllowedRoutes()
	require.False(t, hasRoute(netip.MustParsePrefix("0.0.0.0/0"), v4),
		"revoked v4 route must be gone")
	require.Equal(t, []string{v6.String()}, conn.Addresses())

	// Re-adding programs it again.
	require.NoError(t, conn.SetAddresses([]string{v6.String(), v4.String()}))
	require.Equal(t, 2, countPrefix(rtr.addAddrs, v4))

	// Close removes both families from the router and tears down the VNI.
	require.NoError(t, conn.Close())
	require.Equal(t, 2, countPrefix(rtr.delAddrs, v4), "v4 /32 must be released on close")
	require.GreaterOrEqual(t, countPrefix(rtr.delAddrs, v6), 1, "primary v6 must be released on close")

	_, ok = h.GetVirtualNetwork(vni)
	require.False(t, ok, "VNI must be removed on close")
}

// TestConnectionAdvertisedRoutes asserts that a connection's advertised CIDRs
// are installed as router routes and VNI allowed routes on SetVNI (the transit
// path for traffic to endpoints behind the agent), survive a VNI change
// without double-programming, and are removed on Close.
func TestConnectionAdvertisedRoutes(t *testing.T) {
	v6 := netip.MustParsePrefix("fd00:dead::7/96")
	advertised := netip.MustParsePrefix("10.30.0.0/24")

	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)

	rtr := &recordingRouter{}
	conn := &connection{
		id:               "conn-advertised",
		handler:          h,
		router:           rtr,
		localAddr:        netip.MustParseAddrPort("127.0.0.1:6081"),
		remoteAddr:       netip.MustParseAddrPort("127.0.0.1:7081"),
		advertisedRoutes: []netip.Prefix{advertised},
	}

	require.NoError(t, conn.SetOverlayAddress(v6.String()))
	require.NoError(t, conn.SetVNI(context.Background(), 88))

	require.Equal(t, 1, countPrefix(rtr.addRoutes, advertised),
		"advertised CIDR must be installed as a router route")
	vnet, ok := h.GetVirtualNetwork(88)
	require.True(t, ok)
	foundDst := false
	for _, r := range vnet.AllowedRoutes() {
		if r.Dst == advertised {
			foundDst = true
		}
	}
	require.True(t, foundDst, "advertised CIDR must be in the VNI allowed routes")

	// A VNI change re-creates the virtual network (new trie entries) but must
	// not re-program the VNI-agnostic kernel route.
	require.NoError(t, conn.SetVNI(context.Background(), 89))
	require.Equal(t, 1, countPrefix(rtr.addRoutes, advertised),
		"VNI change must not double-program the advertised route")

	require.NoError(t, conn.Close())
	require.Equal(t, 1, countPrefix(rtr.delRoutes, advertised),
		"advertised route must be removed on close")
}

// TestConnectionPrimaryPromotion asserts SetAddresses and SetOverlayAddress
// compose in either order: a prefix already programmed as an extra is promoted
// to primary in place, never programmed twice.
func TestConnectionPrimaryPromotion(t *testing.T) {
	v6 := netip.MustParsePrefix("fd00:beef::5/96")

	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)

	rtr := &recordingRouter{}
	conn := &connection{
		id:         "conn-promotion",
		handler:    h,
		router:     rtr,
		localAddr:  netip.MustParseAddrPort("127.0.0.1:6081"),
		remoteAddr: netip.MustParseAddrPort("127.0.0.1:7081"),
	}

	require.NoError(t, conn.SetAddresses([]string{v6.String()}))
	require.Equal(t, 1, countPrefix(rtr.addAddrs, v6))

	require.NoError(t, conn.SetOverlayAddress(v6.String()))
	require.Equal(t, 1, countPrefix(rtr.addAddrs, v6), "promotion must not program the prefix twice")
	require.Empty(t, rtr.delAddrs, "promotion must not unprogram anything")
	require.Equal(t, v6.String(), conn.OverlayAddress())
	require.Equal(t, []string{v6.String()}, conn.Addresses())
}
