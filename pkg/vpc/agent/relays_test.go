// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// reachRevision is the first revision of an agent that opens a peer session to
// an agent on another relay.
const reachRevision = 10

// beforeReach is the version of a build one revision before reachRevision.
func beforeReach() *dp.Version {
	return &dp.Version{Revision: reachRevision - 1, Build: "before-reach"}
}

// meshRelays returns a new world with two relays of one mesh.
func meshRelays(t *testing.T) (w *world, r1, r2 *testRelay) {
	t.Helper()
	w = newWorld(t)
	w.mesh = true
	r1, r2 = w.relay(t, "relay-1"), w.relay(t, "relay-2")
	joinMesh(t, r1, r2)
	return w, r1, r2
}

// resolved waits until the relay of ta has an answer for dst, and returns it.
// The relay has none for an address of another relay before the trunk has keys.
func (ta *testAgent) resolved(t *testing.T, dst netip.Addr) *dp.ResolvePeerResponse {
	t.Helper()
	var res *dp.ResolvePeerResponse
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var err error
		res, err = ta.current().resolve(ctx, dst)
		return err == nil
	}, 10*time.Second, 10*time.Millisecond, "ResolvePeer answer for %s", dst)
	return res
}

// hasRoutes waits until OnRoutes of ta has each prefix of want.
func (ta *testAgent) hasRoutes(t *testing.T, want ...netip.Prefix) {
	t.Helper()
	require.Eventually(t, func() bool {
		got := ta.routeSet()
		return !slices.ContainsFunc(want, func(p netip.Prefix) bool { return !slices.Contains(got, p) })
	}, 5*time.Second, 10*time.Millisecond, "routes %v", want)
}

// relayDrops returns the packets that r dropped, by reason.
func relayDrops(t *testing.T, r *testRelay) map[string]uint64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(r.r))
	families, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]uint64{}
	for _, f := range families {
		if f.GetName() != "apoxy_vpc_relay_dropped_packets_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			if n := uint64(m.GetCounter().GetValue()); n > 0 {
				out[m.GetLabel()[0].GetValue()] = n
			}
		}
	}
	return out
}

// meshDrops returns the drops of relayDrops on the paths between two relays.
// It leaves out trunk_no_row: a first packet can come before its row.
func meshDrops(t *testing.T, relays ...*testRelay) []string {
	t.Helper()
	var out []string
	for _, r := range relays {
		for reason, n := range relayDrops(t, r) {
			if reason != "trunk_no_row" && (strings.HasPrefix(reason, "trunk_") || strings.HasPrefix(reason, "mesh_")) {
				out = append(out, fmt.Sprintf("%s %s %d", r.id, reason, n))
			}
		}
	}
	return out
}

// spiCount returns the number of SPIs that p registered at its relay.
func spiCount(p *peer) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.spis)
}

// peersOf returns the peer sessions of a.
func peersOf(a *Agent) []*peer {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Collect(maps.Values(a.peers))
}

// TestPeerOnOtherRelay sends UDP both ways between agent a on relay-1 and agent b
// on relay-2: to the address, to a route and to a second attachment of b.
func TestPeerOnOtherRelay(t *testing.T) {
	cases := []struct {
		name string
		a, b TransportMode
		both bool // Both agents dial at the same time.
		// bridge is true when the data goes through relay SAs or in data frames,
		// and false when each agent has SAs of the other agent.
		bridge bool
	}{
		{name: "PSP to PSP", a: TransportPSP, b: TransportPSP},
		{name: "PSP to PSP, both agents dial", a: TransportPSP, b: TransportPSP, both: true},
		{name: "QUIC to QUIC", a: TransportQUIC, b: TransportQUIC, bridge: true},
		{name: "QUIC to QUIC, both agents dial", a: TransportQUIC, b: TransportQUIC, both: true, bridge: true},
		{name: "PSP to QUIC", a: TransportPSP, b: TransportQUIC, bridge: true},
		{name: "QUIC to PSP", a: TransportQUIC, b: TransportPSP, bridge: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
			a := w.agent(t, "a", r1, agentOptions{mode: tc.a})
			b := w.agent(t, "b", r2, agentOptions{mode: tc.b, routes: []netip.Prefix{route}})
			ea, eb := a.attached(t), b.attached(t)
			b.netstack(t, b.binding(), far, false)
			echo(t, b.stack, eb.addr, 9000)
			echo(t, b.stack, far, 9001)
			echo(t, a.stack, ea.addr, 9002)
			a.hasRoutes(t, eb.prefixes[0], route)
			b.hasRoutes(t, ea.prefixes[0])

			// The answer names the agent b: its subject and its attachment.
			res := a.resolved(t, eb.addr)
			assert.Equal(t, dp.Reach_REACH_TRUNK, res.GetReach())
			assert.Equal(t, b.current().cred.ID.String(), res.GetSubject())
			assert.Equal(t, []string{b.current().attachmentID}, res.GetAttachmentIds())
			assert.Equal(t, dp.Reach_REACH_TRUNK, b.resolved(t, ea.addr).GetReach())

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if tc.both {
				var wg sync.WaitGroup
				var errA, errB error
				wg.Go(func() { errA = a.a.Connect(ctx, eb.addr) })
				wg.Go(func() { errB = b.a.Connect(ctx, ea.addr) })
				wg.Wait()
				require.NoError(t, errA)
				require.NoError(t, errB)
			}
			// With no session, the first packet opens it through the two relays.
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b")
			ping(t, b.stack, eb.addr, ea.addr, 9002, "to a")
			// A QUIC pair keeps the two sessions of crossed dials. A PSP pair keeps one.
			kept := func(n int) bool { return n == 1 || (tc.both && tc.bridge && n == 2) }
			require.Eventually(t, func() bool { return kept(peerCount(a.a)) && kept(peerCount(b.a)) },
				5*time.Second, 10*time.Millisecond, "sessions that stay")
			pas, pbs := peersOf(a.a), peersOf(b.a)
			require.Len(t, pbs, len(pas))
			if !tc.both {
				assert.True(t, pas[0].dialer, "a dialed")
				assert.False(t, pbs[0].dialer, "b took the session")
			}

			// Each agent sends to its own relay, in the form of its pair.
			spis := map[*testAgent]int{}
			for _, side := range []struct {
				name  string
				ta    *testAgent
				peers []*peer
			}{{"a", a, pas}, {"b", b, pbs}} {
				rc := side.ta.current()
				for _, p := range side.peers {
					assert.Equal(t, unmap(rc.relayAddr), unmap(p.bp.Addr()), "address of the peer of %s", side.name)
					assert.Equal(t, tc.bridge, p.quic)
					if tc.bridge {
						assert.Same(t, rc.relay, p.bp)
					} else {
						assert.NotZero(t, rxCountOf(p.bp).packets, "packets with the SAs of the pair at %s", side.name)
					}
					spis[side.ta] += spiCount(p)
				}
			}
			a.a.mu.Lock()
			assert.True(t, pas[0].matches(res), "the answer is for the agent of the session")
			a.a.mu.Unlock()
			if tc.bridge {
				assert.Zero(t, spis[a]+spis[b], "SPIs at the relays")
			} else {
				// The agents have SAs of each other, and use no SA of a relay.
				assert.NotZero(t, spis[a], "SPIs of a at relay-1")
				assert.NotZero(t, spis[b], "SPIs of b at relay-2")
				assert.Zero(t, rxCountOf(a.current().relay).packets, "packets with the SAs of a for relay-1")
				assert.Zero(t, rxCountOf(b.current().relay).packets, "packets with the SAs of b for relay-2")
			}

			ping(t, a.stack, ea.addr, far, 9001, "to a route of b")

			// A second attachment of b uses the same session, with its grant.
			x, err := b.a.Attach(ctx, AttachmentSpec{Name: "b-2"})
			require.NoError(t, err)
			echo(t, b.stack, x.Address, 9003)
			a.hasRoutes(t, x.Prefixes[0])
			both := a.resolved(t, x.Address)
			assert.Equal(t, dp.Reach_REACH_TRUNK, both.GetReach())
			assert.ElementsMatch(t, []string{b.current().attachmentID, x.ID}, both.GetAttachmentIds())
			ping(t, a.stack, ea.addr, x.Address, 9003, "to b-2")
			ping(t, b.stack, x.Address, ea.addr, 9002, "from b-2")
			assert.ElementsMatch(t, pas, peersOf(a.a), "a keeps its peer sessions")
			assert.ElementsMatch(t, pbs, peersOf(b.a), "b keeps its peer sessions")
			assert.Zero(t, unreachableIn(a)+unreachableIn(b), "ICMP errors")
			assert.Empty(t, meshDrops(t, r1, r2), "drops between the relays")

			// When b leaves, relay-1 removes its routes, and a closes the session.
			b.stop()
			require.Eventually(t, func() bool {
				return peerCount(a.a) == 0 && !slices.Contains(a.routeSet(), eb.prefixes[0])
			}, 5*time.Second, 10*time.Millisecond, "a has no session and no route of b")
			send(t, a.stack, ea.addr, eb.addr, 9000, "after b left")
			require.Eventually(t, func() bool { return unreachableIn(a) == 1 }, 5*time.Second, 10*time.Millisecond)
			assert.Zero(t, peerCount(a.a))
		})
	}
}

// TestFirstPacketOnOtherRelay sends to an agent on another relay with no peer
// session, and checks that the echo comes with no wait of a failed open.
func TestFirstPacketOnOtherRelay(t *testing.T) {
	cases := []struct {
		name string
		mode TransportMode
	}{{"PSP", TransportPSP}, {"QUIC", TransportQUIC}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			a := w.agent(t, "a", r1, agentOptions{mode: tc.mode})
			b := w.agent(t, "b", r2, agentOptions{mode: tc.mode})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			a.hasRoutes(t, eb.prefixes[0])
			a.resolved(t, eb.addr)

			// A packet each 200 ms: a first packet that drops at relay-2 costs one interval.
			start := time.Now()
			got := firstEcho(t, a.stack, ea.addr, eb.addr, 9000, 200*time.Millisecond, 3*time.Second)
			require.False(t, got.IsZero(), "no echo in 3 s")
			t.Logf("first echo after %d ms, drops of relay-1 %v, drops of relay-2 %v",
				got.Sub(start).Milliseconds(), relayDrops(t, r1), relayDrops(t, r2))
			// The agent did not mark b as failed, and it keeps the session.
			assert.Zero(t, a.a.Stats().HoldDrops)
			assert.Zero(t, unreachableIn(a), "ICMP errors")
			assert.Equal(t, 1, peerCount(a.a))
			assert.Empty(t, meshDrops(t, r1, r2), "drops between the relays")
			ping(t, a.stack, ea.addr, eb.addr, 9000, "second packet")
		})
	}
}

// TestPeerAfterMoveToOtherRelay checks that an agent that moves to a spare session
// on another relay sends to a peer that stays on the first relay, and gets its packets.
func TestPeerAfterMoveToOtherRelay(t *testing.T) {
	cases := []struct {
		name string
		mode TransportMode
	}{{"PSP", TransportPSP}, {"QUIC", TransportQUIC}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			a := w.agent(t, "a", nil, agentOptions{mode: tc.mode, relays: []identity.Relay{r1.ref(), r2.ref()}, sessions: 2})
			ea := a.attached(t)
			require.Eventually(t, func() bool { return a.spare() != nil }, 10*time.Second, 10*time.Millisecond)
			from, to := r1, r2
			if a.current().addr == r2.addr {
				from, to = r2, r1
			}
			// b has only the first relay of a, so it stays there.
			b := w.agent(t, "b", from, agentOptions{mode: tc.mode})
			eb := b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			echo(t, a.stack, ea.addr, 9001)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "on one relay")
			assert.Equal(t, dp.Reach_REACH_LOCAL, a.resolved(t, eb.addr).GetReach())

			// The attached session of a ends, so a moves to its spare.
			a.reconnect()
			moved := a.attached(t)
			require.Equal(t, to.addr, a.current().addr, "relay of a after the move")
			echo(t, a.stack, moved.addr, 9001)

			// The peer session on the first relay ended. The new one goes over the trunk.
			assert.Equal(t, dp.Reach_REACH_TRUNK, a.resolved(t, eb.addr).GetReach())
			ping(t, a.stack, moved.addr, eb.addr, 9000, "to the relay before the move")
			b.hasRoutes(t, moved.prefixes[0])
			ping(t, b.stack, eb.addr, moved.addr, 9001, "to the relay after the move")
			require.Eventually(t, func() bool { return peerCount(a.a) == 1 && peerCount(b.a) == 1 },
				5*time.Second, 10*time.Millisecond, "one session stays")
			assert.Same(t, a.current(), onlyPeer(t, a.a).rc, "the peer session of a is on its new relay session")
			assert.Equal(t, unmap(a.current().relayAddr), unmap(onlyPeer(t, a.a).bp.Addr()))
		})
	}
}

// TestPeerAfterDrain drains the relay of agent a, which moves to the first of the
// other relays. Agent b is on that relay or on a third relay, and does not move.
func TestPeerAfterDrain(t *testing.T) {
	cases := []struct {
		name  string
		mode  TransportMode
		third bool // b is on the relay that a does not move to.
	}{
		{name: "PSP, peer on the new relay", mode: TransportPSP},
		{name: "PSP, peer on a third relay", mode: TransportPSP, third: true},
		{name: "QUIC, peer on the new relay", mode: TransportQUIC},
		{name: "QUIC, peer on a third relay", mode: TransportQUIC, third: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.mesh = true
			r1, r2, r3 := w.relay(t, "relay-1"), w.relay(t, "relay-2"), w.relay(t, "relay-3")
			joinMesh(t, r1, r2, r3)
			home, want := r2, dp.Reach_REACH_LOCAL
			if tc.third {
				home, want = r3, dp.Reach_REACH_TRUNK
			}
			a := w.agent(t, "a", r1, agentOptions{mode: tc.mode, sessions: 1})
			b := w.agent(t, "b", home, agentOptions{mode: tc.mode, sessions: 1})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			echo(t, a.stack, ea.addr, 9001)
			a.hasRoutes(t, eb.prefixes[0])
			assert.Equal(t, dp.Reach_REACH_TRUNK, a.resolved(t, eb.addr).GetReach())
			ping(t, a.stack, ea.addr, eb.addr, 9000, "before the drain")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				r1.srv.Drain(ctx, r1.mesh.Alternates())
			}()
			moved := a.attached(t)
			require.Equal(t, r2.addr, a.current().addr, "relay of a after the drain")
			select {
			case <-done:
				require.NoError(t, ctx.Err(), "the agent closed its session before the drain time ended")
			case <-time.After(10 * time.Second):
				t.Fatal("drain did not end")
			}
			echo(t, a.stack, moved.addr, 9001)

			// The peer session through relay-1 ended. The new one starts at relay-2.
			assert.Equal(t, want, a.resolved(t, eb.addr).GetReach())
			ping(t, a.stack, moved.addr, eb.addr, 9000, "after the drain")
			b.hasRoutes(t, moved.prefixes[0])
			ping(t, b.stack, eb.addr, moved.addr, 9001, "to the relay after the drain")
			require.Eventually(t, func() bool { return peerCount(a.a) == 1 && peerCount(b.a) == 1 },
				5*time.Second, 10*time.Millisecond, "one session stays")
			assert.Same(t, a.current(), onlyPeer(t, a.a).rc, "the peer session of a is on its new relay session")
		})
	}
}

// TestOlderAgentOnOtherRelay checks that an agent that gets no REACH_TRUNK answer
// takes the peer session that an agent of this build on another relay dials.
func TestOlderAgentOnOtherRelay(t *testing.T) {
	cases := []struct {
		name      string
		version   func() *dp.Version
		localOnly bool
	}{
		{name: "agent one revision before", version: beforeReach},
		{name: "agent of revision 5", version: revision5},
		{name: "agent from before revisions", version: beforeRevisions},
		{name: "agent with local routes only", localOnly: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			a := w.agent(t, "a", r1, agentOptions{})
			b := w.agent(t, "b", r2, agentOptions{version: tc.version, localRoutesOnly: tc.localOnly})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			echo(t, a.stack, ea.addr, 9001)
			a.hasRoutes(t, eb.prefixes[0])
			assert.Equal(t, dp.Reach_REACH_TRUNK, a.resolved(t, eb.addr).GetReach())

			// relay-2 gives b no answer for a, so b opens no session.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := b.current().resolve(ctx, ea.addr)
			require.Equal(t, rpc.NotFound, rpc.CodeOf(err), "answer of relay-2 to b: %v", err)

			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b")
			ping(t, b.stack, eb.addr, ea.addr, 9001, "to a")
			assert.True(t, onlyPeer(t, a.a).dialer)
			assert.False(t, onlyPeer(t, b.a).dialer)
			assert.Empty(t, meshDrops(t, r1, r2), "drops between the relays")
		})
	}
}

// TestDialReach checks which ResolvePeer answers make the agent dial the peer.
func TestDialReach(t *testing.T) {
	cases := []struct {
		reach dp.Reach
		dials bool
	}{
		{dp.Reach_REACH_LOCAL, true},
		{dp.Reach_REACH_TRUNK, true},
		{dp.Reach_REACH_VISIT, false},
		{dp.Reach_REACH_UNSPECIFIED, false},
	}
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	for _, tc := range cases {
		t.Run(tc.reach.String(), func(t *testing.T) {
			a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			p, err := a.a.dial(ctx, a.current(), eb.addr, &dp.ResolvePeerResponse{Reach: tc.reach})
			if !tc.dials {
				require.ErrorContains(t, err, "relay has no path to peer "+eb.addr.String())
				assert.Zero(t, peerCount(a.a))
				assert.Zero(t, peerCount(b.a))
				return
			}
			require.NoError(t, err)
			require.NoError(t, a.a.waitKeys(ctx, p, eb.addr))
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b")
			assert.Same(t, p, onlyPeer(t, a.a))
		})
	}
}

// TestAttachPrefixLimit checks that the agent gets the error of a relay with a
// mesh for an attachment with too many prefixes, and keeps its session.
func TestAttachPrefixLimit(t *testing.T) {
	// The attachment has one address prefix more than its routes.
	const limit = 64
	cases := []struct {
		name    string
		mesh    bool
		routes  int
		refused bool
	}{
		{name: "relay with a mesh, at the limit", mesh: true, routes: limit - 1},
		{name: "relay with a mesh, above the limit", mesh: true, routes: limit, refused: true},
		{name: "relay with no mesh, above the limit", routes: limit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.mesh = tc.mesh
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{})
			a.attached(t)
			spec := AttachmentSpec{Name: "big"}
			for i := range tc.routes {
				spec.Routes = append(spec.Routes, netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i)))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rc := a.current()
			_, err := a.a.Attach(ctx, spec)
			if !tc.refused {
				require.NoError(t, err)
				assert.Len(t, a.a.Attachments(), 2)
				return
			}
			require.Equal(t, rpc.InvalidArgument, rpc.CodeOf(err), "error %v", err)
			assert.ErrorContains(t, err, fmt.Sprintf("attachment has %d addresses and routes, and a relay with a mesh takes at most %d", limit+1, limit))
			assert.Len(t, a.a.Attachments(), 1, "the agent keeps no attachment that the relay refused")
			assert.Equal(t, 1, w.addrs.LiveOf(rc.cred.ID.String()), "only the base attachment keeps its addresses")
			// The session stays, and takes an attachment that fits.
			spec.Routes = spec.Routes[:1]
			_, err = a.a.Attach(ctx, spec)
			require.NoError(t, err)
			assert.Same(t, rc, a.current())
		})
	}
}
