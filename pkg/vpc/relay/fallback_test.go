// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// cut drops the packets that a relay sends to the sockets of another relay while it is on. With a
// cut on each relay, the path between them is cut both ways.
type cut struct {
	on atomic.Bool
	mu sync.Mutex
	to []netip.AddrPort
}

func (c *cut) wrap(pc net.PacketConn) net.PacketConn { return cutConn{PacketConn: pc, c: c} }

// peer makes c drop the packets to the QUIC and data sockets of e.
func (c *cut) peer(e *env) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.to = append(c.to, e.quic.AddrPort(), e.data.AddrPort())
}

func (c *cut) drops(addr net.Addr) bool {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || !c.on.Load() {
		return false
	}
	ap := netip.AddrPortFrom(ua.AddrPort().Addr().Unmap(), ua.AddrPort().Port())
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.to, ap)
}

type cutConn struct {
	net.PacketConn
	c *cut
}

func (cc cutConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if cc.c.drops(addr) {
		return len(b), nil
	}
	return cc.PacketConn.WriteTo(b, addr)
}

// cutMesh starts relay-1 and relay-2 of one mesh with a path between them that the test can cut.
// It returns the function that cuts the path (true) or heals it (false).
func cutMesh(t *testing.T) (e1, e2 *env, setCut func(bool)) {
	t.Helper()
	c1, c2 := &cut{}, &cut{}
	e1, e2 = newMesh(t,
		envOpts{quicSend: c1.wrap, dataSend: c1.wrap},
		envOpts{quicSend: c2.wrap, dataSend: c2.wrap})
	c1.peer(e2)
	c2.peer(e1)
	return e1, e2, func(on bool) {
		c1.on.Store(on)
		c2.on.Store(on)
	}
}

// attachRank attaches the agent with the rank of its connection and returns the answer.
func (a *agent) attachRank(rank uint32) *dpv1.AttachResponse {
	a.t.Helper()
	res, err := a.rc.Attach(context.Background(), &dpv1.AttachRequest{Vpc: vpcRef, Name: a.name, Rank: rank})
	require.NoError(a.t, err)
	return res
}

// report sends the remote addresses of attachment id: the addresses of attachment far on relay.
func (a *agent) report(id, relayID, far string, addrs ...string) {
	a.t.Helper()
	require.NoError(a.t, a.st.Send(&dpv1.SessionRequest{Msg: &dpv1.SessionRequest_Remote{Remote: &dpv1.RemoteAddresses{
		AttachmentId: id,
		Attachments:  []*dpv1.RemoteAttachment{{RelayId: relayID, AttachmentId: far, Addresses: addrs}},
	}}}))
}

// delivers sends one packet from src to dst on the connection of a, and reports whether to gets a
// packet from src to dst in d.
func (a *agent) delivers(to *agent, src, dst netip.Addr, d time.Duration) bool {
	a.sendFrame(packet(src, dst, 100))
	deadline := time.Now().Add(d)
	for left := d; left > 0; left = time.Until(deadline) {
		b := to.recvFrame(left)
		if b == nil {
			return false
		}
		if len(b) >= 40 && netip.AddrFrom16([16]byte(b[8:24])) == src && netip.AddrFrom16([16]byte(b[24:40])) == dst {
			return true
		}
	}
	return false
}

// waitDelivers waits until a packet of a from src to dst reaches to.
func (a *agent) waitDelivers(to *agent, src, dst netip.Addr) {
	a.t.Helper()
	require.Eventually(a.t, func() bool { return a.delivers(to, src, dst, 100*time.Millisecond) }, wait, time.Millisecond,
		"%s to %s from %s to %s", a.name, to.name, src, dst)
}

// drain takes the data frames that wait on the connection.
func (a *agent) drain() {
	for a.recvFrame(50*time.Millisecond) != nil {
	}
}

// drops returns the packets that the data plane of e dropped for reason.
func (e *env) drops(t *testing.T, reason string) float64 {
	t.Helper()
	n, _ := metric(t, e.r, "apoxy_vpc_relay_dropped_packets_total", "reason", reason)
	return n
}

// waitUp waits until e has a mesh session with peer.
func (e *env) waitUp(t *testing.T, peer *env) {
	t.Helper()
	require.Eventually(t, func() bool { return e.r.Up(peer.id) }, 3*wait, 10*time.Millisecond, "%s up at %s", peer.id, e.id)
}

// overlay returns the overlay address of p.
func overlay(p string) netip.Addr { return relay.OverlayAddr(netip.MustParsePrefix(p)) }

// TestFallbackChecks reports addresses on the standby connection of x on relay-2. A packet of x
// passes the source check only from an address that relay-2 took.
func TestFallbackChecks(t *testing.T) {
	// Each relay gives the next /96 of its slot: x and then z on relay-1, y on relay-2.
	cases := []struct {
		name string
		// addr returns the reported address from the addresses of x on relay-1 and y on relay-2.
		addr  func(x, y string) string
		taken bool
		// zLater makes z attach on relay-1 after the report, with the reported address.
		zLater bool
	}{
		{name: "address of x on relay-1", addr: func(x, _ string) string { return x }, taken: true},
		{name: "address outside the VPC", addr: func(string, string) string { return "fd00:99::/96" }},
		{name: "address of the wrong length", addr: func(string, string) string { return "fd61:706f:7879:12:3400:9:0:0/112" }},
		{name: "address of an attachment of relay-2", addr: func(_, y string) string { return y }},
		{name: "address of another agent", addr: func(string, string) string { return "fd61:706f:7879:12:3400:2::/96" }},
		{name: "address that another agent gets later", addr: func(string, string) string { return "fd61:706f:7879:12:3400:2::/96" }, taken: true, zLater: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e1, e2 := newMesh(t, envOpts{}, envOpts{})
			x1 := e1.dial(t, "agent-x")
			x1.open(dpv1.Mode_MODE_QUIC)
			resX1 := x1.attachRank(0)
			x2 := e2.dial(t, "agent-x")
			x2.open(dpv1.Mode_MODE_QUIC)
			resX2 := x2.attachRank(1)
			y := e2.dial(t, "agent-y")
			y.open(dpv1.Mode_MODE_QUIC)
			resY := y.attach()
			z := e1.dial(t, "agent-z")
			z.open(dpv1.Mode_MODE_QUIC)
			pa, py := resX1.GetAddresses()[0], resY.GetAddresses()[0]
			if !tc.zLater {
				resZ := z.attach()
				require.Equal(t, "fd61:706f:7879:12:3400:2::/96", resZ.GetAddresses()[0])
				// relay-2 has the record of z.
				y.waitDelivers(z, overlay(py), addr(t, resZ))
			}
			bad := tc.addr(pa, py)
			src := overlay(bad)

			// Before the report, a packet of x from its address on relay-1 drops at relay-2.
			before := e2.drops(t, "source")
			assert.False(t, x2.delivers(y, overlay(pa), overlay(py), 300*time.Millisecond))
			assert.Equal(t, before+1, e2.drops(t, "source"))

			// The report has the address of x on relay-1 and the address of the case. A packet from
			// the address of x on relay-1 tells that relay-2 took the report.
			x2.report(resX2.GetAttachmentId(), "relay-1", resX1.GetAttachmentId(), pa, bad)
			x2.waitDelivers(y, overlay(pa), overlay(py))
			if bad == pa {
				return
			}
			y.drain()
			before = e2.drops(t, "source")
			got := x2.delivers(y, src, overlay(py), 300*time.Millisecond)
			assert.Equal(t, tc.taken, got, "packet from %s", src)
			if !tc.taken {
				assert.Equal(t, before+1, e2.drops(t, "source"))
			}
			if !tc.zLater {
				return
			}

			// The packets for the address go to x until z on relay-1 gets it. Then the record of z
			// refuses the address of x.
			y.waitDelivers(x2, overlay(py), src)
			resZ := z.attach()
			require.Equal(t, bad, resZ.GetAddresses()[0])
			y.waitDelivers(z, overlay(py), src)
			x2.drain()
			// The source entries of x go in the next event of its A, after the route write of V.
			assert.Eventually(t, func() bool { return !x2.delivers(y, src, overlay(py), 300*time.Millisecond) },
				wait, 10*time.Millisecond, "packet of x from the address of z")
		})
	}
}

// TestFallbackCut cuts the path between relay-1, where x is at home, and relay-2, where x has a
// standby connection. The packets of y on relay-2 for x go to the fallback, then the trunk again.
func TestFallbackCut(t *testing.T) {
	cases := []struct {
		name   string
		report bool
	}{
		{name: "standby connection reports the address", report: true},
		{name: "standby connection with no report"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e1, e2, setCut := cutMesh(t)
			x1 := e1.dial(t, "agent-x")
			x1.open(dpv1.Mode_MODE_QUIC)
			resX1 := x1.attachRank(0)
			x2 := e2.dial(t, "agent-x")
			x2.open(dpv1.Mode_MODE_QUIC)
			resX2 := x2.attachRank(1)
			y := e2.dial(t, "agent-y")
			y.open(dpv1.Mode_MODE_QUIC)
			resY := y.attach()
			pa, py := addr(t, resX1), addr(t, resY)
			if tc.report {
				x2.report(resX2.GetAttachmentId(), "relay-1", resX1.GetAttachmentId(), resX1.GetAddresses()...)
				x2.waitDelivers(y, pa, py)
			}

			// The trunk carries the packets for x while the path is up.
			assert.Equal(t, "relay-1", y.waitRoute(slot, true).GetRelay().GetId())
			y.waitDelivers(x1, py, pa)
			x2.drain()

			setCut(true)
			assert.Equal(t, relay.MeshChange{Name: "relay-1", Down: relay.MeshLost}, e2.change(t))
			assert.Equal(t, relay.MeshChange{Name: "relay-2", Down: relay.MeshLost}, e1.change(t))
			if tc.report {
				y.waitDelivers(x2, py, pa)
				r := y.route(slot)
				require.NotNil(t, r, "slot Route of relay-1 in the cut")
				assert.Equal(t, "relay-1", r.GetOrigin())
				assert.Equal(t, "relay-1", r.GetRelay().GetId())
			} else {
				y.waitRoute(slot, false)
				assert.False(t, y.delivers(x2, py, pa, 300*time.Millisecond))
			}

			setCut(false)
			e1.waitUp(t, e2)
			e2.waitUp(t, e1)
			y.waitDelivers(x1, py, pa)
			x2.drain()
			assert.False(t, y.delivers(x2, py, pa, 300*time.Millisecond), "packet for x on the standby connection after the heal")
		})
	}
}

// TestFallbackReplies sends packets of x on relay-2 from its address on relay-1. They go to agents
// on relay-2 only, never to the trunk.
func TestFallbackReplies(t *testing.T) {
	e1, e2 := newMesh(t, envOpts{}, envOpts{})
	x1 := e1.dial(t, "agent-x")
	x1.open(dpv1.Mode_MODE_QUIC)
	resX1 := x1.attachRank(0)
	x2 := e2.dial(t, "agent-x")
	x2.open(dpv1.Mode_MODE_QUIC)
	resX2 := x2.attachRank(1)
	y := e2.dial(t, "agent-y")
	y.open(dpv1.Mode_MODE_QUIC)
	resY := y.attach()
	z := e1.dial(t, "agent-z")
	z.open(dpv1.Mode_MODE_QUIC)
	resZ := z.attach()
	pa := addr(t, resX1)
	// relay-2 has the record of z.
	y.waitDelivers(z, addr(t, resY), addr(t, resZ))
	x2.report(resX2.GetAttachmentId(), "relay-1", resX1.GetAttachmentId(), resX1.GetAddresses()...)
	x2.waitDelivers(y, pa, addr(t, resY))
	y.drain()

	cases := []struct {
		name string
		to   *agent
		dst  netip.Addr
		pass bool
	}{
		{name: "agent of relay-2", to: y, dst: addr(t, resY), pass: true},
		{name: "agent of relay-1", to: z, dst: addr(t, resZ)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trunk, _ := metric(t, e2.r, "apoxy_vpc_relay_trunk_packets_total", "peer_relay", e1.id, "direction", "tx")
			noRoute := e2.drops(t, "no_route")
			assert.Equal(t, tc.pass, x2.delivers(tc.to, pa, tc.dst, 300*time.Millisecond))
			after, _ := metric(t, e2.r, "apoxy_vpc_relay_trunk_packets_total", "peer_relay", e1.id, "direction", "tx")
			assert.Equal(t, trunk, after, "packets of relay-2 to the trunk")
			if !tc.pass {
				assert.Equal(t, noRoute+1, e2.drops(t, "no_route"))
			}
		})
	}
}
