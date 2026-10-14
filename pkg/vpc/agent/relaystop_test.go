// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// muteConn drops each packet of a relay socket while mute is set, as a relay
// that stops and sends nothing.
type muteConn struct {
	net.PacketConn
	mute atomic.Bool
}

func (c *muteConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.mute.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *muteConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(p)
		if err != nil || !c.mute.Load() {
			return n, from, err
		}
	}
}

// TestRelayStops checks that the session on a relay that stops ends at the
// QUIC idle timeout and data goes through the other session, and that a
// session whose PSP port alone stops stays in QUIC mode with its address.
func TestRelayStops(t *testing.T) {
	// The QUIC idle timeout is 6 s, and the test gives 1 s more.
	const within = 7 * time.Second
	cases := []struct {
		name    string
		mode    TransportMode
		pspOnly bool // Only the PSP path between the agent and relay 1 stops.
	}{
		{name: "relay stops in PSP mode"},
		{name: "relay stops in QUIC mode", mode: TransportQUIC},
		{name: "PSP port stops", pspOnly: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.mesh = true
			quic1, psp1 := &muteConn{PacketConn: loopback(t)}, &muteConn{PacketConn: loopback(t)}
			r1, r2 := w.relayOn(t, "relay-1", quic1, psp1), w.relay(t, "relay-2")
			joinMesh(t, r1, r2)
			route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
			// The relays send trunk data on their PSP sockets, so the agent drops
			// the PSP packets of relay 1 when only the PSP port stops.
			block := &blockConn{relay: r1.psp}
			a, rcs := w.agentOn(t, "a", agentOptions{mode: tc.mode, block: block, routes: []netip.Prefix{route}}, 2, r1, r2)
			b := w.agent(t, "b", r2, agentOptions{})
			eb := b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			a.netstack(t, a.binding(), far, false)
			a.hasRoutes(t, eb.prefixes[0])
			b.hasRoutes(t, route)
			lost := rcs[0]
			require.Same(t, lost, a.current())
			ping(t, a.stack, far, eb.addr, 9000, "from the advertised network before")
			want := dp.Mode_MODE_PSP
			if tc.mode == TransportQUIC {
				want = dp.Mode_MODE_QUIC
			}
			require.Equal(t, want, lost.dataMode())

			if tc.pspOnly {
				block.out.Store(true)
				block.in.Store(true)
				require.Eventually(t, func() bool { return lost.dataMode() == dp.Mode_MODE_QUIC }, 10*time.Second, 10*time.Millisecond,
					"the session did not change to QUIC mode")
				require.Never(t, func() bool { return lost.qc.Context().Err() != nil }, within, 50*time.Millisecond,
					"the session ended while its QUIC port answers")
				assert.Same(t, lost, a.current(), "the session keeps the default address")
				assert.Equal(t, lost.self, a.a.Status().Connections[0].Address)
				assert.NotContains(t, a.events("a"), "detach a "+lost.self.String())
				ping(t, a.stack, far, eb.addr, 9000, "from the advertised network in QUIC mode")
				return
			}
			stopped := time.Now()
			quic1.mute.Store(true)
			psp1.mute.Store(true)
			select {
			case <-lost.qc.Context().Done():
			case <-time.After(within):
				t.Fatalf("the session on the relay that stopped did not end in %v", within)
			}
			t.Logf("The session ended %v after the relay stopped.", time.Since(stopped))
			var idle *quic.IdleTimeoutError
			assert.ErrorAs(t, context.Cause(lost.qc.Context()), &idle)
			require.Eventually(t, func() bool { return a.current() == rcs[1] }, time.Second, 10*time.Millisecond,
				"the session on relay 2 did not get the default address")
			require.Eventually(t, func() bool { return slices.Contains(a.events("a"), "detach a "+lost.self.String()) }, time.Second, 10*time.Millisecond,
				"the address of the session that ended stays")
			ping(t, a.stack, far, eb.addr, 9000, "from the advertised network after")
			ping(t, a.stack, rcs[1].self, eb.addr, 9000, "from the address of relay 2 after")
		})
	}
}
