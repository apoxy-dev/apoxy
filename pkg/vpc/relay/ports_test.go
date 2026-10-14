// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// modeOf returns the data mode of s.
func modeOf(r *Router, s *Session) dp.Mode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return s.sync.mode
}

// TestSessionStart checks that each session starts in QUIC mode with the PSP
// address of the relay in Welcome, and that only a path probe permits PSP mode.
func TestSessionStart(t *testing.T) {
	cases := []struct {
		name  string
		hello dp.Mode
	}{
		{"Hello in QUIC mode", dp.Mode_MODE_QUIC},
		{"Hello in PSP mode", dp.Mode_MODE_PSP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			st, err := a.c.Session(context.Background())
			require.NoError(t, err)
			require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: tc.hello}}}))
			w := recv(t, st).GetWelcome()
			require.NotNil(t, w)
			assert.Empty(t, w.GetPspHost(), "the agent sends to the host that it dialed")
			assert.EqualValues(t, addrPort(h.pspAddr).Port(), w.GetPspPort())
			assert.Equal(t, a.src.String(), w.GetReflexiveAddress())
			require.NotNil(t, recv(t, st).GetConfig())
			s := h.session(t, a)
			assert.Equal(t, dp.Mode_MODE_QUIC, modeOf(h.r, s))
			assert.False(t, h.r.Addr(s).IsValid(), "PSP address before a probe")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			offer := keyproto.ToProto(newPSPReceiver(t, time.Now()).req)
			_, err = a.c.Rekey(ctx, offer)
			assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "Rekey before a probe: %v", err)
			assert.Equal(t, dp.Mode_MODE_QUIC, modeOf(h.r, s))

			probeTo(t, a, h.pspAddr)
			assert.Equal(t, a.src, h.r.Addr(s))
			_, err = a.c.Rekey(ctx, offer)
			require.NoError(t, err)
			assert.Equal(t, dp.Mode_MODE_PSP, modeOf(h.r, s))
			var keys *dp.KeysRequest
			for keys == nil {
				keys = recv(t, st).GetRekey()
			}
			assert.Zero(t, h.r.drops[dropNotQUIC].Load())
		})
	}
}

// newTwoSocketNode returns a trunk node with a QUIC socket and a PSP socket, as
// a relay host has them. All nodes are at one IP address, each with its own ports.
func newTwoSocketNode(t *testing.T, ca *testCA, name string) *trunkNode {
	t.Helper()
	n := &trunkNode{meshNode: newNode(t, ca, name, false), r: NewRouter(nil, Config{})}
	psp := &quic.Transport{Conn: loopbackUDP(t)}
	psp.NonQUICPacketHandler, psp.NonQUICBatchEnd = n.r.PacketHandler(n.ctx, psp)
	require.NoError(t, psp.Start())
	t.Cleanup(func() { _ = psp.Close() })
	n.psp = psp
	n.tr.NonQUICPacketHandler = n.r.QUICSocketHandler()
	n.m.SetRouter(n.r)
	return n
}

// TestTrunkTwoSockets starts two relays at one IP address with different PSP ports. Each one sends
// trunk packets to the PSP port that the other gave in Open, and a trunk packet to a QUIC socket drops.
func TestTrunkTwoSockets(t *testing.T) {
	ca := newCA(t)
	a, b := newTwoSocketNode(t, ca, "relay-a"), newTwoSocketNode(t, ca, "relay-b")
	a.m.SetMembers([]MeshMember{b.member()})
	b.m.SetMembers([]MeshMember{a.member()})
	b.start(t)
	a.start(t)
	require.Equal(t, MeshChange{Name: "relay-b", Up: true}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, b.change(t, 10*time.Second))
	keyed(t, a, b)
	require.Equal(t, a.addr.Addr(), b.addr.Addr(), "the two relays have one IP address")
	require.NotEqual(t, addrPort(a.psp.Conn.LocalAddr()).Port(), addrPort(b.psp.Conn.LocalAddr()).Port())
	for _, d := range []struct{ n, peer *trunkNode }{{a, b}, {b, a}} {
		assert.Equal(t, addrPort(d.peer.psp.Conn.LocalAddr()), d.n.trunk().to(d.peer.name).addr,
			"%s sends to the PSP port of %s", d.n.name, d.peer.name)
		// The probes of the trunk pass only between the PSP sockets.
		require.Eventually(t, func() bool { return d.n.path(d.peer.name) == trunkPathFull },
			10*time.Second, 10*time.Millisecond, "%s: probe result for %s", d.n.name, d.peer.name)
	}

	snd := newRelayEnd(t, a, dp.Mode_MODE_QUIC, "laptop", "fd00:1::/96")
	rcv := newRelayEnd(t, b, dp.Mode_MODE_QUIC, "server", prefixA)
	require.Eventually(t, func() bool { return routeTable(a.r, vpcA)[prefixA] == "att-server@relay-b" },
		10*time.Second, 5*time.Millisecond, "relay-a has the route of the attachment of relay-b")
	require.Eventually(t, func() bool { return routeTable(b.r, vpcA)["fd00:1::/96"] == "att-laptop@relay-a" },
		10*time.Second, 5*time.Millisecond, "relay-b has the attachment of the sender")
	inner := innerOf(snd.addr, rcv.addr, 48)
	snd.send(t, inner)
	got, vni := rcv.recv(t)
	assert.Equal(t, inner, got)
	assert.EqualValues(t, testVNI, vni)
	assert.EqualValues(t, 1, socketCounts(b.r)["member_trunk"])
	for _, n := range []*trunkNode{a, b} {
		assert.Zero(t, n.r.drops[dropNotQUIC].Load(), "%s: packets on the QUIC socket that are not QUIC", n.name)
		assert.Empty(t, dropsOf(n.r), n.name)
	}

	// A trunk packet to the QUIC socket of relay-b drops there.
	pkt := sealTrunk(t, a, "relay-b", trunkLane, trunkTagRelay, []byte{trunkMsgProbe}, true)
	_, err := a.psp.WriteTo(pkt, net.UDPAddrFromAddrPort(b.addr))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return b.r.drops[dropNotQUIC].Load() == 1 }, 5*time.Second, 5*time.Millisecond)
	assert.EqualValues(t, 1, socketCounts(b.r)["member_trunk"])
}

// TestPSPSocket checks the PSP socket that a relay takes from the Open of a member.
func TestPSPSocket(t *testing.T) {
	dialed := netip.MustParseAddr("192.0.2.1")
	cases := []struct {
		name    string
		host    string
		port    uint32
		want    string // Empty means no PSP socket.
		wantErr bool
	}{
		{name: "empty host is the dialed host", port: 1000, want: "192.0.2.1:1000"},
		{name: "set host", host: "198.51.100.7", port: 1001, want: "198.51.100.7:1001"},
		{name: "IPv4-mapped host", host: "::ffff:198.51.100.7", port: 1001, want: "198.51.100.7:1001"},
		{name: "host that is not an IP address", host: "relay.example.net", port: 1000, wantErr: true},
		{name: "port 0 is no PSP socket", host: "198.51.100.7"},
		{name: "port above the range", port: 65536, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pspSocket(tc.host, tc.port, dialed)
			require.Equal(t, tc.wantErr, err != nil, "error: %v", err)
			if tc.want == "" {
				assert.False(t, got.IsValid())
				return
			}
			assert.Equal(t, tc.want, got.String())
		})
	}
}
