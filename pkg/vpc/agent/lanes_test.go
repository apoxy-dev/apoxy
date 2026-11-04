// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestLanes checks the lane ports that an agent registers at its relay. The
// relay peer has one SA lane, so the PSP packets go on lane 0, and the relay
// takes the keepalives of the lane ports.
func TestLanes(t *testing.T) {
	loopbackHost := hostList(addrs("127.0.0.1"))
	cases := []struct {
		name       string
		relayLanes int       // Lane port limit of the relay.
		lanes      int       // Config.Lanes of the agents.
		anyAddr    bool      // The agent sockets are on all IPv4 addresses, not on 127.0.0.1.
		hosts      HostAddrs // Config.Addresses of the agents.
		natPort    bool      // The relay sees agent a at its IP with another port.
		want       int       // Lane sockets of the agent.
	}{
		{name: "relay takes the lane ports", relayLanes: relay.MaxLaneSources, lanes: 4, hosts: loopbackHost, want: 3},
		{name: "relay limit below the queues", relayLanes: 2, lanes: 8, hosts: loopbackHost, want: 2},
		{name: "relay takes no lane ports", lanes: 4, hosts: loopbackHost},
		{name: "one queue", relayLanes: relay.MaxLaneSources, lanes: 1, hosts: loopbackHost},
		{
			name: "socket on all addresses sees a host address", relayLanes: relay.MaxLaneSources, lanes: 4, anyAddr: true,
			hosts: hostList(addrs("192.0.2.10", "127.0.0.1")), want: 3,
		},
		// The relay sees 127.0.0.1 at the port of the agent socket, which is not a host address:
		// a NAT that keeps the port.
		{name: "port-preserving NAT", relayLanes: relay.MaxLaneSources, lanes: 4, anyAddr: true, hosts: hostList(addrs("192.0.2.10"))},
		{name: "NAT that changes the port", relayLanes: relay.MaxLaneSources, lanes: 4, hosts: loopbackHost, natPort: true},
		{name: "no host list", relayLanes: relay.MaxLaneSources, lanes: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock := func() *net.UDPConn {
				if tc.anyAddr {
					return listen(t, "udp4")
				}
				return loopback(t)
			}
			w := newWorld(t)
			w.relayCfg = relay.Config{LaneSources: tc.relayLanes}
			udp := sock()
			// The relay sees the port of the agent socket, or the port of the NAT.
			port := localAddrPort(udp).Port()
			var r *testRelay
			if tc.natPort {
				// A socket that stays open keeps the NAT port for this test.
				held := loopback(t)
				t.Cleanup(func() { _ = held.Close() })
				from, to := localAddrPort(udp), localAddrPort(held)
				port = to.Port()
				r = w.relayOn(t, "relay-1", &natConn{loopback(t), from, to}, &natConn{loopback(t), from, to})
			} else {
				r = w.relay(t, "relay-1")
			}
			a := w.agent(t, "a", r, agentOptions{udp: udp, lanes: tc.lanes, hosts: tc.hosts})
			b := w.agent(t, "b", r, agentOptions{udp: sock(), lanes: tc.lanes, hosts: tc.hosts})
			ea, eb := a.attached(t), b.attached(t)
			require.Eventually(t, func() bool { return a.a.Status().Mode == dp.Mode_MODE_PSP }, 10*time.Second, 10*time.Millisecond,
				"the session commits to PSP mode")
			require.True(t, slices.ContainsFunc(a.a.Status().Candidates, func(c Candidate) bool {
				return c.Kind == CandidateReflexive && c.Address.Port() == port
			}), "reflexive address at the port %d: %v", port, a.a.Status().Candidates)
			echo(t, b.stack, eb.addr, 9000)
			for i := range 8 {
				ping(t, a.stack, ea.addr, eb.addr, 9000, fmt.Sprintf("flow %d", i))
			}
			assert.Len(t, a.binding().LaneConns(), tc.want, "lane sockets")
			assert.Len(t, a.binding().LanePackets(), 1, "packets of each lane: %v", a.binding().LanePackets())
			assert.NotZero(t, a.binding().LanePackets()[0])
			assert.Zero(t, relayDrops(t, r)["unknown_source"])
			assert.Zero(t, relayDrops(t, r)["malformed"], "the relay takes the lane keepalives")
		})
	}
}

// natConn is a relay socket behind a NAT: the relay sees the agent socket at
// from as at to, and its packets to to go to from.
type natConn struct {
	net.PacketConn
	from, to netip.AddrPort
}

func (c *natConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if ua, ok := addr.(*net.UDPAddr); ok && unmap(ua.AddrPort()) == c.from {
		addr = net.UDPAddrFromAddrPort(c.to)
	}
	return n, addr, err
}

func (c *natConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if ua, ok := addr.(*net.UDPAddr); ok && unmap(ua.AddrPort()) == c.to {
		addr = net.UDPAddrFromAddrPort(c.from)
	}
	return c.PacketConn.WriteTo(p, addr)
}
