// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pspPackets returns the sum of the PSP packet counts of the lanes of a binding.
func pspPackets(lanes []uint64) (n uint64) {
	for _, c := range lanes {
		n += c
	}
	return n
}

// visitPair returns agent a on relay-1 and agent b on relay-2 of one mesh, with
// echo servers on port 9000.
func visitPair(t *testing.T, optsA, optsB agentOptions) (r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent) {
	t.Helper()
	w, r1, r2 := meshRelays(t)
	a = w.agent(t, "a", r1, optsA)
	ea = a.attached(t)
	b = w.agent(t, "b", r2, optsB)
	eb = b.attached(t)
	echo(t, a.stack, ea.addr, 9000)
	echo(t, b.stack, eb.addr, 9000)
	a.hasRoutes(t, eb.prefixes[0])
	b.hasRoutes(t, ea.prefixes[0])
	return r1, r2, a, b, ea, eb
}

// visits reports whether ta routes dst through a visit of the relay r.
func visits(ta *testAgent, r *testRelay, dst netip.Addr) bool {
	for _, rt := range ta.visitRoutes() {
		if p, err := netip.ParsePrefix(rt.Dst); rt.Via == r.id && (err == nil && p.Contains(dst) || rt.Dst == dst.String()) {
			return true
		}
	}
	return false
}

// TestVisit cuts the mesh path between the relays of agents a and b. The first
// packet of a to b gives a NoRoute with the relay of b, so a visits that relay,
// and the data goes on the visitor session in each pair of modes.
func TestVisit(t *testing.T) {
	cases := []struct {
		name         string
		modeA, modeB TransportMode // a is the visitor.
	}{
		{name: "PSP visitor to PSP agent", modeA: TransportAuto, modeB: TransportAuto},
		{name: "QUIC visitor to PSP agent", modeA: TransportQUIC, modeB: TransportAuto},
		{name: "PSP visitor to QUIC agent", modeA: TransportAuto, modeB: TransportQUIC},
		{name: "QUIC visitor to QUIC agent", modeA: TransportQUIC, modeB: TransportQUIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r1, r2, a, b, ea, eb := visitPair(t, agentOptions{mode: tc.modeA, visitCheck: time.Hour}, agentOptions{mode: tc.modeB, visitCheck: time.Hour})
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b over the trunk")
			home := a.current()

			t.Cleanup(cutMesh(r1, r2))
			waitCut(t, r1, r2)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "first packet after the cut")
			require.True(t, visits(a, r2, eb.addr), "a routes b through a visit of relay-2: %v", a.a.Routes())
			assert.Empty(t, b.visitRoutes(), "b does not visit")
			assert.Zero(t, unreachableIn(a)+unreachableIn(b), "ICMP errors")

			sent := func() uint64 { return pspPackets(a.binding().LanePackets()) }
			before := sent()
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a on the visit")
			if tc.modeA == TransportQUIC {
				// An agent in QUIC mode seals no PSP packet, and only the home relay has extra connections.
				assert.Zero(t, sent(), "PSP packets of a")
				assert.Len(t, r2.agentConns(a.tr.Conn.LocalAddr(), true), 1, "connections of a at the visited relay")
			} else {
				require.Eventually(t, func() bool {
					ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit in PSP mode")
					return sent() > before
				}, 10*time.Second, 100*time.Millisecond, "a seals PSP packets on the visit")
			}
			sameSession(t, home, a.current(), "the attached session stays")

			// The visit ends with the agent.
			a.stop()
			require.Eventually(t, func() bool { return len(r2.agentConns(a.tr.Conn.LocalAddr(), true)) == 0 }, 5*time.Second, 20*time.Millisecond,
				"the visitor session closed")
		})
	}
}

// TestVisitReturn checks when a visit ends.
func TestVisitReturn(t *testing.T) {
	cases := []struct {
		name string
		// heal: the mesh path comes back. moved: a gets a new attached session.
		heal, moved bool
	}{
		{name: "home relay reaches the address again", heal: true},
		{name: "attachment moved", moved: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r1, r2, a, b, ea, eb := visitPair(t, agentOptions{mode: TransportAuto, visitCheck: 100 * time.Millisecond},
				agentOptions{mode: TransportAuto, visitCheck: time.Hour})
			heal := cutMesh(r1, r2)
			waitCut(t, r1, r2)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "on the visit")
			require.True(t, visits(a, r2, eb.addr), "a visits relay-2")
			// relay-1 does not reach b, so the checks keep the visit.
			require.Never(t, func() bool { return !visits(a, r2, eb.addr) }, 500*time.Millisecond, 50*time.Millisecond, "the visit ended")

			switch {
			case tc.heal:
				heal()
				joinMesh(t, r1, r2)
			case tc.moved:
				a.reconnect()
				a.attached(t)
			}
			require.Eventually(t, func() bool { return len(a.visitRoutes()) == 0 }, 10*time.Second, 20*time.Millisecond, "the visit ends")
			require.Eventually(t, func() bool { return len(r2.agentConns(a.tr.Conn.LocalAddr(), true)) == 0 }, 5*time.Second, 20*time.Millisecond,
				"the visitor session closed")
			if tc.heal {
				ping(t, a.stack, ea.addr, eb.addr, 9000, "to b over the trunk")
				ping(t, b.stack, eb.addr, ea.addr, 9000, "to a over the trunk")
			}
		})
	}
}

// TestVisitAttachments checks that the agent of the visited relay reaches each
// attachment of the visitor, old and new, but not one that detached.
func TestVisitAttachments(t *testing.T) {
	cases := []struct {
		name         string
		modeA, modeB TransportMode // a is the visitor.
	}{
		{name: "PSP visitor to PSP agent", modeA: TransportAuto, modeB: TransportAuto},
		{name: "QUIC visitor to PSP agent", modeA: TransportQUIC, modeB: TransportAuto},
		{name: "QUIC visitor to QUIC agent", modeA: TransportQUIC, modeB: TransportQUIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r1, r2, a, b, ea, eb := visitPair(t, agentOptions{mode: tc.modeA, visitCheck: time.Hour}, agentOptions{mode: tc.modeB, visitCheck: time.Hour})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			x, err := a.a.Attach(ctx, AttachmentSpec{Name: "a-2"})
			require.NoError(t, err)
			echo(t, a.stack, x.Address, 9001)

			t.Cleanup(cutMesh(r1, r2))
			waitCut(t, r1, r2)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit")
			require.True(t, visits(a, r2, eb.addr), "a visits relay-2")
			ping(t, b.stack, eb.addr, x.Address, 9001, "to a-2 on the visit")
			ping(t, a.stack, x.Address, eb.addr, 9000, "from a-2 on the visit")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to the first attachment on the visit")

			// An attachment that a adds in the visit goes in the visit too.
			y, err := a.a.Attach(ctx, AttachmentSpec{Name: "a-3"})
			require.NoError(t, err)
			echo(t, a.stack, y.Address, 9002)
			ping(t, b.stack, eb.addr, y.Address, 9002, "to a-3 on the visit")
			ping(t, a.stack, y.Address, eb.addr, 9000, "from a-3 on the visit")
			assert.Len(t, r2.agentConns(a.tr.Conn.LocalAddr(), true), 1, "one visitor session has all attachments")
			assert.Empty(t, b.visitRoutes(), "b does not visit")

			// After Detach, b does not reach a-2, and a-3 stays.
			require.NoError(t, a.a.Detach(ctx, "a-2"))
			require.Eventually(t, func() bool { return !answers(b.stack, eb.addr, x.Address, 9001) }, 10*time.Second, 10*time.Millisecond,
				"b reaches a-2 after its Detach")
			ping(t, b.stack, eb.addr, y.Address, 9002, "to a-3 after the Detach of a-2")
		})
	}
}
