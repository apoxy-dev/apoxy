package netstack_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

// TestDeprecateAddr checks the source address that the stack selects for a new
// connection when it has two addresses.
func TestDeprecateAddr(t *testing.T) {
	first, second := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::3")
	cases := []struct {
		name      string
		deprecate []netip.Addr
		remove    []netip.Addr
		want      netip.Addr
	}{
		{name: "first deprecated", deprecate: []netip.Addr{first}, want: second},
		{name: "second deprecated", deprecate: []netip.Addr{second}, want: first},
		{name: "both deprecated, first removed", deprecate: []netip.Addr{first, second}, remove: []netip.Addr{first}, want: second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns, err := netstack.NewStack(netstack.TunnelMTU, "")
			require.NoError(t, err)
			defer ns.Close()
			for _, a := range []netip.Addr{first, second} {
				require.NoError(t, ns.AddAddr(netip.PrefixFrom(a, 128)))
			}
			for _, a := range tc.deprecate {
				require.NoError(t, ns.DeprecateAddr(netip.PrefixFrom(a, 128)))
			}
			for _, a := range tc.remove {
				require.NoError(t, ns.DelAddr(netip.PrefixFrom(a, 128)))
			}
			peer := fullAddr(ns.NICID, peerAddr, 9)
			c, err := gonet.DialUDP(ns.Stack, nil, &peer, ipv6.ProtocolNumber)
			require.NoError(t, err)
			defer c.Close()
			require.Equal(t, tc.want, c.LocalAddr().(*net.UDPAddr).AddrPort().Addr())
		})
	}
}
