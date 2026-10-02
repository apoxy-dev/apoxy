// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestIPv4Sources checks that a peer takes an IPv4 packet only from a source in
// a route of the sender, and that a sender with no IPv4 route reaches an IPv4
// address of a peer in the /96 of that peer.
func TestIPv4Sources(t *testing.T) {
	lan, far := netip.MustParsePrefix("10.1.0.0/24"), netip.MustParseAddr("10.1.0.5")
	src := netip.MustParseAddr("192.0.2.10")
	own := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	cases := []struct {
		name     string
		mode     TransportMode
		routes   []netip.Prefix // Of the sender.
		embedded bool           // To far in the /96 of the peer, from the overlay address of the sender.
		answer   bool
	}{
		{name: "PSP source in a route", mode: TransportPSP, routes: own, answer: true},
		{name: "PSP source in no route", mode: TransportPSP},
		{name: "PSP IPv4 in the /96 of the peer", mode: TransportPSP, embedded: true, answer: true},
		{name: "QUIC source in a route", mode: TransportQUIC, routes: own, answer: true},
		{name: "QUIC source in no route", mode: TransportQUIC},
		{name: "QUIC IPv4 in the /96 of the peer", mode: TransportQUIC, embedded: true, answer: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{mode: tc.mode, routes: tc.routes})
			b := w.agent(t, "b", r, agentOptions{mode: tc.mode, routes: []netip.Prefix{lan}})
			ea, eb := a.attached(t), b.attached(t)
			from, to := src, far
			if tc.embedded {
				b16 := eb.addr.As16()
				copy(b16[12:], far.AsSlice())
				from, to = ea.addr, netip.AddrFrom16(b16)
				b.netstack(t, b.binding(), to, false)
			} else {
				addIPv4(t, a.stack, from)
				addIPv4(t, b.stack, to)
				require.Eventually(t, func() bool { return slices.Contains(a.routeSet(), lan) },
					5*time.Second, 10*time.Millisecond)
			}
			echo(t, b.stack, to, 9000)
			require.Equal(t, tc.answer, answers(a.stack, from, to, 9000))
			if !tc.answer {
				// PSP drops at the destination, QUIC at the relay.
				st := b.binding().Stats()
				assert.Zero(t, st.RxPackets)
				if tc.mode == TransportPSP {
					assert.NotZero(t, st.RxDrops)
				}
			}
		})
	}
}

// netProto returns the network protocol of addr.
func netProto(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

// addIPv4 adds addr and an IPv4 route to the netstack s.
func addIPv4(t *testing.T, s *stack.Stack, addr netip.Addr) {
	t.Helper()
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
	if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("add address: %v", err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
}

// answers reports whether dst:port sends back a UDP packet from src, in 3 tries.
func answers(s *stack.Stack, src, dst netip.Addr, port uint16) bool {
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), netProto(dst))
	if err != nil {
		return false
	}
	defer c.Close()
	buf := make([]byte, 1500)
	for range 3 {
		if _, err := c.Write([]byte("ping")); err != nil {
			return false
		}
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := c.Read(buf); err == nil {
			return true
		}
	}
	return false
}
