// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// blockConn drops the packets between the agent socket and the PSP socket of
// a relay. The QUIC socket has another address, so the relay session stays.
type blockConn struct {
	net.PacketConn
	relay   string // Address of the PSP socket of the relay.
	out, in atomic.Bool
	// half drops each second BFD packet to the relay.
	half   atomic.Bool
	probes atomic.Int32
}

func (c *blockConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr.String() == c.relay {
		probe := len(p) > 0 && p[0] == p2p.TypeProbe
		if c.out.Load() || (probe && c.half.Load() && c.probes.Add(1)%2 == 0) {
			return len(p), nil
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *blockConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(p)
		if err != nil || !c.in.Load() || from.String() != c.relay {
			return n, from, err
		}
	}
}

// TestPSPPathLost checks that a session whose PSP packets stop changes to QUIC
// mode and back, and keeps its address, attachment and open TCP connection.
func TestPSPPathLost(t *testing.T) {
	retry := [3]time.Duration{0, 400 * time.Millisecond}
	cases := []struct {
		name    string
		out, in bool // Directions of the PSP path of a that drop each packet.
		half    bool // The path to the relay drops each second BFD packet.
	}{
		{name: "1 of 2 BFD packets lost", half: true},
		{name: "both directions", out: true, in: true},
		{name: "packets to the relay", out: true},
		{name: "packets from the relay", in: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			block := &blockConn{relay: r.psp}
			a, b := w.agent(t, "a", r, agentOptions{block: block, tcp: true, pspRetry: retry}), w.agent(t, "b", r, agentOptions{tcp: true})
			ea, eb := a.attached(t), b.attached(t)
			serveTCP(t, b.stack, eb.addr, 9000)
			c := dialTCP(t, a, eb.addr, 9000)
			roundTrip(t, c, "in PSP mode")
			rc, id, events := a.current(), a.a.Attachments()[0].ID, a.events("a")
			same := func() {
				t.Helper()
				sameSession(t, rc, a.current(), "the agent has the same relay session")
				assert.Equal(t, ea.addr, a.a.Status().Connections[0].Address)
				assert.Equal(t, id, a.a.Attachments()[0].ID)
				assert.Empty(t, a.attach, "the agent attached again")
				assert.Equal(t, events, a.events("a"), "callbacks of the address")
			}

			if tc.half {
				block.half.Store(true)
				require.Never(t, func() bool { return a.a.Status().Mode != dp.Mode_MODE_PSP }, 2*bfdl.DefaultDetectMult*checkTx, 50*time.Millisecond,
					"the session left PSP mode")
				assert.Greater(t, block.probes.Load(), int32(bfdl.DefaultDetectMult), "BFD packets of the agent")
				roundTrip(t, c, "with BFD packets lost")
				same()
				return
			}
			block.out.Store(tc.out)
			block.in.Store(tc.in)
			// TCP sends the lost segments again, as QUIC data.
			roundTripIn(t, c, "after the PSP packets stop", 30*time.Second)
			st := a.a.Status()
			assert.Equal(t, dp.Mode_MODE_QUIC, st.Mode)
			assert.Equal(t, dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT, st.Reason)
			same()

			block.out.Store(false)
			block.in.Store(false)
			require.Eventually(t, func() bool { return a.a.Status().Mode == dp.Mode_MODE_PSP }, 30*time.Second, 10*time.Millisecond,
				"the session did not return to PSP mode")
			roundTrip(t, c, "back in PSP mode")
			same()
		})
	}
}

// TestVisitPSPPathLost checks an agent with a visit when the PSP path of one
// of its two sessions stops. The data of the visit stays.
func TestVisitPSPPathLost(t *testing.T) {
	retry := [3]time.Duration{0, 400 * time.Millisecond}
	cases := []struct {
		name string
		home bool // The path of the attached session stops, not that of the visit.
	}{
		{name: "path of the visitor session"},
		{name: "path of the attached session", home: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, r1, r2 := meshRelays(t)
			block := &blockConn{relay: r2.psp}
			if tc.home {
				block.relay = r1.psp
			}
			a := w.agent(t, "a", r1, agentOptions{block: block, visitCheck: time.Hour, pspRetry: retry})
			ea := a.attached(t)
			b := w.agent(t, "b", r2, agentOptions{visitCheck: time.Hour})
			eb := b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			a.hasRoutes(t, eb.prefixes[0])
			b.hasRoutes(t, ea.prefixes[0])
			t.Cleanup(cutMesh(r1, r2))
			waitCut(t, r1, r2)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "on the visit")
			require.NotEmpty(t, a.visitRoutes(), "a visits relay-2")
			home := a.current()
			same := func(msg string) {
				t.Helper()
				sameSession(t, home, a.current(), "%s: relay session of the agent", msg)
				assert.Equal(t, ea.addr, home.self, "%s: address of the agent", msg)
				assert.Empty(t, a.attach, "%s: the agent attached again", msg)
				assert.NotEmpty(t, a.visitRoutes(), "%s: the visit stays", msg)
			}

			block.out.Store(true)
			block.in.Store(true)
			if tc.home {
				require.Eventually(t, func() bool { return a.a.Status().Mode == dp.Mode_MODE_QUIC }, 15*time.Second, 10*time.Millisecond,
					"the session did not change to QUIC mode")
				assert.Equal(t, dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT, a.a.Status().Reason)
			}
			// The session of the lost path changes to QUIC mode after the BFD detect time.
			require.Eventually(t, func() bool { return answers(a.stack, ea.addr, eb.addr, 9000) }, 15*time.Second, 10*time.Millisecond,
				"no data on the visit after the path stopped")
			same("path lost")

			block.out.Store(false)
			block.in.Store(false)
			if tc.home {
				require.Eventually(t, func() bool { return a.a.Status().Mode == dp.Mode_MODE_PSP }, 45*time.Second, 10*time.Millisecond,
					"the session did not go back to PSP mode")
			}
			ping(t, a.stack, ea.addr, eb.addr, 9000, "on the visit after the return")
			same("path back")
		})
	}
}

// TestPathSizeLost lowers the path size under a session in PSP mode. The large
// BFD packets drop, so the session changes to QUIC mode, and then back to PSP
// mode with the TCP MSS clamp, where BFD stays Up.
func TestPathSizeLost(t *testing.T) {
	const detect = bfdl.DefaultDetectMult * checkTx
	w := newWorld(t)
	w.mtu = 1400
	r := w.relay(t, "relay-1")
	conn := &lossyConn{}
	a, b := w.agent(t, "a", r, agentOptions{conn: conn, pspRetry: [3]time.Duration{time.Second, 2 * time.Second, 300 * time.Millisecond}}),
		w.agent(t, "b", r, agentOptions{})
	ea, eb := a.attached(t), b.attached(t)
	rc, bind := a.current(), a.binding()
	mode := func() dp.Mode { return a.a.Status().Mode }
	require.Equal(t, dp.Mode_MODE_PSP, mode())
	require.Zero(t, bind.ClampMTU())
	echo(t, b.stack, eb.addr, 9000)
	ping(t, a.stack, ea.addr, eb.addr, 9000, "before the path change")
	// tooBig sends an inner packet above QUICMTU, which gets packet too big.
	tooBig := func(msg string) {
		t.Helper()
		c, err := gonet.DialUDP(a.stack, fullAddr(ea.addr, 0), fullAddr(eb.addr, 9000), ipv6.ProtocolNumber)
		require.NoError(t, err)
		defer c.Close()
		before := bind.Stats().TxTooBig
		require.Eventually(t, func() bool {
			_, _ = c.Write(make([]byte, 1300))
			return bind.Stats().TxTooBig > before
		}, 5*time.Second, 50*time.Millisecond, "no packet too big %s", msg)
	}

	conn.max.Store(psp.QUICMTU + pspwire.Overhead)
	require.Eventually(t, func() bool { return mode() == dp.Mode_MODE_QUIC }, detect+2*checkTx, 10*time.Millisecond,
		"BFD stayed Up on a path that drops large packets")
	assert.Equal(t, dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT, a.a.Status().Reason)
	tooBig("in QUIC mode")

	require.Eventually(t, func() bool { return mode() == dp.Mode_MODE_PSP }, 15*time.Second, 10*time.Millisecond,
		"the session did not return to PSP mode")
	assert.Equal(t, psp.QUICMTU, bind.ClampMTU(), "TCP MSS clamp")
	tooBig("in PSP mode with the clamp")
	require.Never(t, func() bool { return mode() != dp.Mode_MODE_PSP }, detect+checkTx, 50*time.Millisecond,
		"BFD went Down on the path with the clamp")
	ping(t, a.stack, ea.addr, eb.addr, 9000, "after the return to PSP mode")
	sameSession(t, rc, a.current(), "the agent has the same relay session")
}
