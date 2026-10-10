// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// relayRef returns r as a relay gives it to an agent.
func (r *testRelay) relayRef() *dp.RelayRef {
	return &dp.RelayRef{Id: r.id, Addresses: []string{r.addr}}
}

// visitAnswer is the ResolvePeer answer that sends an agent to r as a visitor.
func visitAnswer(r *testRelay) *dp.ResolvePeerResponse {
	return &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_VISIT, HomeRelay: r.relayRef()}
}

// visitOf returns the visit of a on r after its setup, or nil.
func visitOf(a *Agent, r *testRelay) *visit {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v := a.visits[r.id]; v != nil && v.session() != nil {
		return v
	}
	return nil
}

// visitCount returns the number of visits of a, with the ones that open.
func visitCount(a *Agent) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.visits)
}

// peerOn returns the open peer session of a on rc that covers dst, or nil.
func peerOn(a *Agent, rc *relayConn, dst netip.Addr) *peer {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peerTo(rc, dst)
}

// waitReach waits until the relay of ta answers ResolvePeer for dst with want.
func waitReach(t *testing.T, ta *testAgent, dst netip.Addr, want dp.Reach) {
	t.Helper()
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		res, err := ta.current().resolve(ctx, dst)
		return err == nil && res.GetReach() == want
	}, 15*time.Second, 20*time.Millisecond, "answer %v for %s", want, dst)
}

// pathDown reports whether the path of p is down.
func pathDown(a *Agent, p *peer) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return p.down
}

// keyed reports whether the two sides of p have SAs.
func keyed(p *peer) bool {
	for _, ch := range []chan struct{}{p.keyed, p.offered} {
		select {
		case <-ch:
		default:
			return false
		}
	}
	return true
}

// dialOnVisit opens the visit of ta to r and dials dst on it. It does not wait
// for the visit of the peer, and it keeps the other sessions of ta.
func dialOnVisit(t *testing.T, ctx context.Context, ta *testAgent, r *testRelay, dst netip.Addr) (*visit, error) {
	t.Helper()
	v, err := ta.a.visit(ctx, ta.current(), r.relayRef())
	require.NoError(t, err)
	defer ta.a.release(v)
	return v, ta.a.connect(ctx, v.rc, dst, nil)
}

// oneVisit waits until a and b have one peer session on one visit after a cut.
// Then it opens the path with heal, and waits for a session over the trunk.
func oneVisit(t *testing.T, a, b *testAgent, ea, eb attachEvent, heal func()) {
	t.Helper()
	old := onlyPeer(t, a.a)
	// The visit with no peer ends at its check.
	var pa, pb *peer
	require.Eventually(t, func() bool {
		if peerCount(a.a) != 1 || peerCount(b.a) != 1 || visitCount(a.a)+visitCount(b.a) != 1 {
			return false
		}
		pa, pb = onlyPeer(t, a.a), onlyPeer(t, b.a)
		// A session with the path down gives its place to the session of a new visit.
		return pa.rc.visitor != pb.rc.visitor && keyed(pa) && keyed(pb) && !pathDown(a.a, pa) && !pathDown(b.a, pb)
	}, 20*time.Second, 20*time.Millisecond, "one peer session on one visit")
	assert.Error(t, old.qc.Context().Err(), "the session over the trunk closed")
	// With a visit of a, the session on that visit stays. Else it is on the visit of b.
	assert.True(t, keeps(pa.rc, eb.addr) || visitCount(a.a) == 0, "the session that stays")
	ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit")
	ping(t, b.stack, eb.addr, ea.addr, 9000, "to a on the visit")
	assert.Same(t, pa, onlyPeer(t, a.a), "the session stays")
	assert.Same(t, pb, onlyPeer(t, b.a), "the session stays")

	heal()
	require.Eventually(t, func() bool {
		return visitCount(a.a)+visitCount(b.a) == 0 &&
			peerOn(a.a, a.current(), eb.addr) != nil && peerOn(b.a, b.current(), ea.addr) != nil
	}, 30*time.Second, 20*time.Millisecond, "peer session on the attached sessions")
	ping(t, a.stack, ea.addr, eb.addr, 9000, "to b over the trunk")
	ping(t, b.stack, eb.addr, ea.addr, 9000, "to a over the trunk")
}

// visitPair returns agent a on relay-1 and agent b on relay-2 of one mesh, with
// echo servers on port 9000. a attaches first, so it has the lower address.
func visitPair(t *testing.T, optsA, optsB agentOptions) (r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent) {
	t.Helper()
	w, r1, r2 := meshRelays(t)
	a = w.agent(t, "a", r1, optsA)
	ea = a.attached(t)
	b = w.agent(t, "b", r2, optsB)
	eb = b.attached(t)
	require.True(t, ea.addr.Less(eb.addr), "a has the lower address")
	echo(t, a.stack, ea.addr, 9000)
	echo(t, b.stack, eb.addr, 9000)
	a.hasRoutes(t, eb.prefixes[0])
	b.hasRoutes(t, ea.prefixes[0])
	return r1, r2, a, b, ea, eb
}

// TestVisitRules checks which agent of a pair visits, and which answers of a
// relay need no visit.
func TestVisitRules(t *testing.T) {
	low, high := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	turns := []struct {
		name       string
		self, peer netip.Addr
		want       bool
	}{
		{"lower address", low, high, true},
		{"higher address", high, low, false},
		{"same address", low, low, false},
	}
	for _, tc := range turns {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, visits(tc.self, tc.peer))
		})
	}
	// The session on the relay of the higher address stays: the visit of the lower.
	stays := []struct {
		name       string
		self, peer netip.Addr
		visitor    bool
		want       bool
	}{
		{"lower address, visitor session", low, high, true, true},
		{"lower address, attached session", low, high, false, false},
		{"higher address, visitor session", high, low, true, false},
		{"higher address, attached session", high, low, false, true},
	}
	for _, tc := range stays {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, keeps(&relayConn{self: tc.self, visitor: tc.visitor}, tc.peer))
		})
	}
	reaches := []struct {
		reach dp.Reach
		want  bool
	}{
		{dp.Reach_REACH_LOCAL, true},
		{dp.Reach_REACH_TRUNK, true},
		{dp.Reach_REACH_VISIT, false},
		{dp.Reach_REACH_UNSPECIFIED, false},
	}
	for _, tc := range reaches {
		t.Run(tc.reach.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, reachable(&dp.ResolvePeerResponse{Reach: tc.reach}))
		})
	}

	// A destination fails until the wait of its failure ends.
	var h holds
	now := time.Now()
	h.mu.Lock()
	h.fail(low, errVisitLimit, now)
	h.mu.Unlock()
	fails := []struct {
		name string
		dst  netip.Addr
		at   time.Time
		want bool
	}{
		{"in the wait", low, now.Add(minRetry / 2), true},
		{"after the wait", low, now.Add(minRetry), false},
		{"other destination", high, now, false},
	}
	for _, tc := range fails {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, h.failing(tc.dst, tc.at))
		})
	}
}

// TestVisit gives agent a the answer REACH_VISIT for agent b on another relay.
// The mesh path is up, so the relay of b takes the visit as with a cut path.
func TestVisit(t *testing.T) {
	cases := []struct {
		name       string
		mode       TransportMode
		spare      bool // a has a spare session on the relay of b.
		dropProbes bool // The path probes of the visitor session get no reply.
		data       bool // Data goes on the visitor session.
	}{
		{name: "PSP", mode: TransportPSP, data: true},
		{name: "PSP, spare session on the relay of the peer", mode: TransportPSP, spare: true, data: true},
		{name: "PSP, path probe fails", mode: TransportPSP, dropProbes: true},
		{name: "QUIC", mode: TransportQUIC, data: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			conn := &lossyConn{}
			opts := agentOptions{mode: tc.mode, conn: conn, visitCheck: time.Hour}
			if tc.spare {
				opts.relays, opts.sessions = []identity.Relay{r1.ref(), r2.ref()}, 2
			}
			a := w.agent(t, "a", r1, opts)
			ea := a.attached(t)
			home, far := r1, r2
			if a.current().addr == r2.addr {
				home, far = r2, r1
			}
			var spare *relayConn
			if tc.spare {
				require.Eventually(t, func() bool { return a.spare() != nil }, 10*time.Second, 10*time.Millisecond)
				spare = a.spare()
				require.Equal(t, far.addr, spare.addr)
			}
			route := netip.MustParsePrefix("fd99::/64")
			b := w.agent(t, "b", far, agentOptions{mode: TransportPSP, routes: []netip.Prefix{route}})
			eb := b.attached(t)
			echo(t, a.stack, ea.addr, 9000)
			echo(t, b.stack, eb.addr, 9000)
			a.hasRoutes(t, eb.prefixes[0], route)
			conn.limitProbes.Store(tc.dropProbes)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rc := a.current()
			err := a.a.connect(ctx, rc, eb.addr, visitAnswer(far))
			if tc.data {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errVisitNoData)
			}

			// The visitor session has the address of a, and the attached session stays.
			v := visitOf(a.a, far)
			require.NotNil(t, v, "visit of %s", far.id)
			assert.Same(t, rc, a.current())
			assert.Same(t, rc, v.home)
			assert.Equal(t, home.addr, rc.addr)
			assert.True(t, v.rc.visitor)
			assert.Equal(t, far.addr, v.rc.addr)
			assert.Equal(t, ea.addr, v.rc.self)
			assert.Equal(t, tc.data, v.rc.data.Load(), "result of the path probe")
			assert.Equal(t, 1, visitCount(a.a))
			// The key changes of a relay peer go to the session of that relay.
			assert.Same(t, rc, a.a.relayOfBinding(rc.relay))
			assert.Same(t, v.rc, a.a.relayOfBinding(v.rc.relay))
			if tc.spare {
				// A spare has the routes of other relays, so it gives its place to the visitor.
				assert.True(t, spare.ended(), "the spare session closed")
				assert.NotSame(t, spare, v.rc)
				assert.Nil(t, a.spare())
			}

			// The peer session is on the visitor session. b took it on its own relay.
			p := onlyPeer(t, a.a)
			assert.Same(t, v.rc, p.rc)
			assert.True(t, p.dialer)
			assert.Equal(t, !tc.data, p.idle)
			require.Eventually(t, func() bool { return peerCount(b.a) == 1 }, 5*time.Second, 10*time.Millisecond)
			assert.False(t, onlyPeer(t, b.a).dialer)
			advertised := func() []netip.Prefix {
				a.a.mu.Lock()
				defer a.a.mu.Unlock()
				return p.advertised
			}
			if !tc.data {
				// Only the peer frames go to the relay of b: a gets no SA, no SPI row and no route.
				assert.ErrorIs(t, p.wait(ctx), errVisitNoData)
				require.Never(t, func() bool { return spiCount(p) != 0 || len(p.bp.RxReport()) != 0 || len(advertised()) != 0 },
					300*time.Millisecond, 20*time.Millisecond, "SAs, SPI rows or routes of a for b")
				return
			}
			assert.Equal(t, []netip.Prefix{route}, advertised())
			assert.Equal(t, unmap(v.rc.relayAddr), unmap(p.bp.Addr()), "data of a goes to the relay of b")
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a")
			if tc.mode == TransportQUIC {
				// The data of a goes as data frames, so a seals and opens no PSP packet.
				assert.True(t, p.quic)
				assert.Zero(t, pspPackets(a.a.bind.LanePackets())+pspPackets(a.a.bind.RxLanePackets()), "PSP packets of a")
			} else {
				assert.NotZero(t, spiCount(p), "SPIs of a at the visited relay")
				assert.NotZero(t, rxCountOf(p.bp).packets, "packets from b on the visitor session")
			}
			assert.Zero(t, unreachableIn(a)+unreachableIn(b), "ICMP errors")
			// The visit ends with the agent.
			a.stop()
			assert.True(t, v.rc.ended(), "the visitor session closed")
			assert.Zero(t, visitCount(a.a))
		})
	}
}

// pspPackets returns the sum of the PSP packet counts of the lanes of a binding.
func pspPackets(lanes []uint64) (n uint64) {
	for _, c := range lanes {
		n += c
	}
	return n
}

// TestVisitData checks for each pair of modes that data goes on the visitor session after a
// cut, that only an agent in PSP mode seals PSP packets, and that data goes back at the end.
func TestVisitData(t *testing.T) {
	cases := []struct {
		name         string
		modeA, modeB TransportMode // a is the visitor.
	}{
		{name: "PSP visitor to PSP peer", modeA: TransportPSP, modeB: TransportPSP},
		{name: "QUIC visitor to PSP peer", modeA: TransportQUIC, modeB: TransportPSP},
		{name: "PSP visitor to QUIC peer", modeA: TransportPSP, modeB: TransportQUIC},
		{name: "QUIC visitor to QUIC peer", modeA: TransportQUIC, modeB: TransportQUIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r1, r2, a, b, ea, eb := visitPair(t,
				agentOptions{mode: tc.modeA, visitCheck: time.Hour},
				agentOptions{mode: tc.modeB, visitCheck: time.Hour, visitWait: time.Hour})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			require.NoError(t, a.a.connect(ctx, a.current(), eb.addr, nil))
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b over the trunk")
			sent := func(ta *testAgent) uint64 { return pspPackets(ta.a.bind.LanePackets()) }
			got := func(ta *testAgent) uint64 { return pspPackets(ta.a.bind.RxLanePackets()) }
			quicA, quicB := tc.modeA == TransportQUIC, tc.modeB == TransportQUIC
			// An agent in QUIC mode seals and opens no PSP packet at all.
			if quicA {
				assert.Zero(t, sent(a)+got(a), "PSP packets of a before the cut")
			}

			heal := cutMesh(r1, r2)
			waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)
			v, err := dialOnVisit(t, ctx, a, r2, eb.addr)
			require.NoError(t, err)
			assert.True(t, v.rc.data.Load(), "data goes on the visitor session")
			assert.Equal(t, quicA, v.rc.mode == dp.Mode_MODE_QUIC, "mode of the visitor session")
			p := peerOn(a.a, v.rc, eb.addr)
			require.NotNil(t, p, "peer session of a on the visit")
			assert.False(t, p.idle)
			assert.Equal(t, quicA || quicB, p.quic, "the relay of b opens the packets")
			require.Eventually(t, func() bool { return peerOn(b.a, b.current(), ea.addr) != nil }, 5*time.Second, 10*time.Millisecond)

			// The trunk is cut, so the two pings go on the visitor session.
			sentA, gotA, sentB, gotB := sent(a), got(a), sent(b), got(b)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a on the visit")
			assert.Equal(t, !quicA, sent(a) > sentA, "a seals PSP packets")
			assert.Equal(t, !quicA, got(a) > gotA, "a opens PSP packets")
			assert.Equal(t, !quicB, sent(b) > sentB, "b seals PSP packets")
			assert.Equal(t, !quicB, got(b) > gotB, "b opens PSP packets")
			assert.Zero(t, unreachableIn(a)+unreachableIn(b), "ICMP errors")
			assert.Equal(t, 1, visitCount(a.a))
			assert.Zero(t, visitCount(b.a), "b does not visit")

			// The visit ends when relay-1 reaches b again, and the data goes back.
			heal()
			waitReach(t, a, eb.addr, dp.Reach_REACH_TRUNK)
			require.Eventually(t, func() bool { return a.a.checkVisit(v) || visitCount(a.a) == 0 }, 10*time.Second, 50*time.Millisecond, "the visit ends")
			assert.True(t, v.rc.ended(), "the visitor session closed")
			require.Eventually(t, func() bool {
				return peerOn(a.a, a.current(), eb.addr) != nil && peerOn(b.a, b.current(), ea.addr) != nil
			}, 10*time.Second, 20*time.Millisecond, "peer session on the attached sessions")
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b over the trunk again")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a over the trunk again")
			if quicA {
				assert.Zero(t, sent(a)+got(a), "PSP packets of a at the end")
			}
		})
	}
}

// liveOn reports whether a has an open peer session on rc with the path up that
// covers dst.
func liveOn(a *Agent, rc *relayConn, dst netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.livePeerTo(rc, dst) != nil
}

// TestVisitAttachments checks that the peer of a visit reaches each attachment
// of the visitor: one from before the visit, and one that attaches in the visit.
// An attachment that detaches in the visit leaves it.
func TestVisitAttachments(t *testing.T) {
	cases := []struct {
		name         string
		modeA, modeB TransportMode // a is the visitor.
	}{
		{name: "PSP visitor to PSP peer", modeA: TransportPSP, modeB: TransportPSP},
		{name: "QUIC visitor to PSP peer", modeA: TransportQUIC, modeB: TransportPSP},
		{name: "QUIC visitor to QUIC peer", modeA: TransportQUIC, modeB: TransportQUIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r1, r2, a, b, ea, eb := visitPair(t,
				agentOptions{mode: tc.modeA, visitCheck: time.Hour},
				agentOptions{mode: tc.modeB, visitCheck: time.Hour, visitWait: time.Hour})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			x, err := a.a.Attach(ctx, AttachmentSpec{Name: "a-2"})
			require.NoError(t, err)
			echo(t, a.stack, x.Address, 9001)

			cutMesh(r1, r2)
			waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)
			v, err := dialOnVisit(t, ctx, a, r2, eb.addr)
			require.NoError(t, err)
			require.True(t, v.rc.data.Load(), "data goes on the visitor session")
			reaches := func(dst netip.Addr) func() bool {
				return func() bool { return liveOn(b.a, b.current(), ea.addr) && liveOn(b.a, b.current(), dst) }
			}
			require.Eventually(t, reaches(x.Address), 5*time.Second, 10*time.Millisecond, "b has the grant of a-2")
			ping(t, b.stack, eb.addr, x.Address, 9001, "to a-2 on the visit")
			ping(t, a.stack, x.Address, eb.addr, 9000, "from a-2 on the visit")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to the first attachment on the visit")

			// An attachment that a adds in the visit goes in the visit too.
			y, err := a.a.Attach(ctx, AttachmentSpec{Name: "a-3"})
			require.NoError(t, err)
			echo(t, a.stack, y.Address, 9002)
			require.Eventually(t, reaches(y.Address), 5*time.Second, 10*time.Millisecond, "b has the grant of a-3")
			ping(t, b.stack, eb.addr, y.Address, 9002, "to a-3 on the visit")
			ping(t, a.stack, y.Address, eb.addr, 9000, "from a-3 on the visit")
			// A late echo of a ping gives an ICMP error of the netstack, so the test
			// counts the packets that an agent did not send.
			assert.Zero(t, a.a.Stats().HoldDrops+b.a.Stats().HoldDrops, "packets with no peer session")
			assert.Equal(t, 1, visitCount(a.a), "one visitor session has all attachments")
			assert.Zero(t, visitCount(b.a), "b does not visit")

			// After Detach, b has no route to a-2, and relay-2 has no visit for it.
			require.NoError(t, a.a.Detach(ctx, "a-2"))
			require.Eventually(t, func() bool { return !liveOn(b.a, b.current(), x.Address) }, 5*time.Second, 10*time.Millisecond, "b lost the grant of a-2")
			_, err = v.rc.c.Detach(ctx, &dp.DetachRequest{AttachmentId: x.ID})
			assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "relay-2 has no visit with the grant of a-2: %v", err)
			ping(t, b.stack, eb.addr, y.Address, 9002, "to a-3 after the Detach of a-2")
			// The relay ends the visit of a-3 on a Detach call, one time.
			_, err = v.rc.c.Detach(ctx, &dp.DetachRequest{AttachmentId: y.ID})
			assert.NoError(t, err, "relay-2 has the visit with the grant of a-3")
			_, err = v.rc.c.Detach(ctx, &dp.DetachRequest{AttachmentId: y.ID})
			assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "second Detach: %v", err)
		})
	}
}

// TestVisitAttachmentsRelayRevision checks that the agent puts its extra
// attachments in a visit only on a relay that takes more than one Visit call.
func TestVisitAttachmentsRelayRevision(t *testing.T) {
	cases := []struct {
		name     string
		revision uint32 // Revision of relay-2 as the agent knows it.
		extras   int    // Extra attachments of a on the visitor session.
	}{
		{name: "relay before the revision", revision: visitExtras - 1},
		{name: "relay at the revision", revision: visitExtras, extras: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r1, r2, a, b, ea, eb := visitPair(t,
				agentOptions{mode: TransportPSP, visitCheck: time.Hour},
				agentOptions{mode: TransportPSP, visitCheck: time.Hour, visitWait: time.Hour})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			x, err := a.a.Attach(ctx, AttachmentSpec{Name: "a-2"})
			require.NoError(t, err)
			cutMesh(r1, r2)
			waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)

			rc, err := a.a.dialRelay(ctx, endpoint{id: r2.id, addr: r2.addr}, spareHello, true)
			require.NoError(t, err)
			defer rc.close()
			rc.version = &dp.Version{Revision: tc.revision}
			require.NoError(t, rc.startVisit(ctx, a.current()))
			require.NoError(t, a.a.connect(ctx, rc, eb.addr, nil))
			require.Eventually(t, func() bool { return liveOn(b.a, b.current(), ea.addr) }, 5*time.Second, 10*time.Millisecond)
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to the first attachment on the visit")

			a.a.mu.Lock()
			n := len(rc.extras)
			a.a.mu.Unlock()
			assert.Equal(t, tc.extras, n, "extra attachments on the visitor session")
			assert.Equal(t, tc.extras == 1, liveOn(b.a, b.current(), x.Address), "b has the grant of a-2")
			// An attachment that a adds then follows the same rule.
			y, err := a.a.Attach(ctx, AttachmentSpec{Name: "a-3"})
			require.NoError(t, err)
			if tc.extras == 1 {
				require.Eventually(t, func() bool { return liveOn(b.a, b.current(), y.Address) }, 5*time.Second, 10*time.Millisecond, "b has the grant of a-3")
			} else {
				a.a.mu.Lock()
				assert.Empty(t, rc.extras)
				a.a.mu.Unlock()
				assert.False(t, liveOn(b.a, b.current(), y.Address), "b has no grant of a-3")
			}
		})
	}
}

// TestVisitLimit checks that a second peer on a visited relay uses the visit and
// the probe result of the first, and that a third relay to visit gives an error.
func TestVisitLimit(t *testing.T) {
	w := newWorld(t)
	w.mesh = true
	r1, r2, r3, r4 := w.relay(t, "relay-1"), w.relay(t, "relay-2"), w.relay(t, "relay-3"), w.relay(t, "relay-4")
	joinMesh(t, r1, r2, r3, r4)
	conn := &lossyConn{}
	a := w.agent(t, "a", r1, agentOptions{mode: TransportPSP, conn: conn, visitCheck: time.Hour})
	ea := a.attached(t)
	peers := []struct {
		name  string
		relay *testRelay
		ta    *testAgent
		addr  netip.Addr
	}{{name: "b", relay: r2}, {name: "c", relay: r2}, {name: "d", relay: r3}, {name: "e", relay: r4}}
	for i := range peers {
		p := &peers[i]
		p.ta = w.agent(t, p.name, p.relay, agentOptions{mode: TransportPSP})
		ev := p.ta.attached(t)
		p.addr = ev.addr
		echo(t, p.ta.stack, ev.addr, 9000)
		a.hasRoutes(t, ev.prefixes[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rc := a.current()
	b, c, d, e := peers[0], peers[1], peers[2], peers[3]

	require.NoError(t, a.a.connect(ctx, rc, b.addr, visitAnswer(r2)))
	probes := conn.probes.Load()
	require.NotZero(t, probes, "path probes of the first visit")
	v := visitOf(a.a, r2)
	require.NotNil(t, v)

	// The second peer on relay-2 opens no session to the relay and sends no probe.
	require.NoError(t, a.a.connect(ctx, rc, c.addr, visitAnswer(r2)))
	assert.Equal(t, probes, conn.probes.Load(), "path probes after the second peer")
	assert.Same(t, v, visitOf(a.a, r2))
	assert.Equal(t, 1, visitCount(a.a))
	require.NotNil(t, peerOn(a.a, v.rc, b.addr), "peer session to b on the visitor session")
	require.NotNil(t, peerOn(a.a, v.rc, c.addr), "peer session to c on the visitor session")

	require.NoError(t, a.a.connect(ctx, rc, d.addr, visitAnswer(r3)))
	assert.Equal(t, 2, visitCount(a.a))

	// A third relay is above the limit. The two visits stay.
	err := a.a.connect(ctx, rc, e.addr, visitAnswer(r4))
	require.ErrorIs(t, err, errVisitLimit)
	assert.ErrorContains(t, err, "visit relay relay-4 for peer "+e.addr.String()+": agent has the most visitor sessions (2)")
	assert.Equal(t, 2, visitCount(a.a))
	assert.Nil(t, visitOf(a.a, r4))
	assert.Equal(t, 3, peerCount(a.a))
	assert.Zero(t, peerCount(e.ta.a), "peer sessions of e")
	for _, p := range []struct {
		name string
		addr netip.Addr
	}{{"b", b.addr}, {"c", c.addr}, {"d", d.addr}} {
		ping(t, a.stack, ea.addr, p.addr, 9000, "to "+p.name)
	}
}

// TestVisitReturn checks when a visit ends, and where its peer session goes.
func TestVisitReturn(t *testing.T) {
	cases := []struct {
		name string
		// left: b stops before the check. moved: a gets a new attached session,
		// and no check runs.
		left, moved bool
	}{
		{name: "home relay reaches the peer again"},
		{name: "peer left", left: true},
		{name: "attachment moved", moved: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, r2, a, b, ea, eb := visitPair(t, agentOptions{mode: TransportPSP, visitCheck: time.Hour}, agentOptions{mode: TransportPSP})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.connect(ctx, a.current(), eb.addr, visitAnswer(r2)))
			v := visitOf(a.a, r2)
			require.NotNil(t, v)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "on the visit")

			switch {
			case tc.moved:
				a.reconnect()
				a.attached(t)
				require.Eventually(t, func() bool { return visitCount(a.a) == 0 }, 5*time.Second, 10*time.Millisecond)
				assert.True(t, v.rc.ended(), "the visitor session closed")
				return
			case tc.left:
				b.stop()
				require.Eventually(t, func() bool { return peerCount(a.a) == 0 }, 5*time.Second, 10*time.Millisecond)
			}
			// The mesh path is up, so relay-1 answers REACH_TRUNK for b while b is there.
			require.True(t, a.a.checkVisit(v), "the visit ended")
			assert.Zero(t, visitCount(a.a))
			assert.True(t, v.rc.ended(), "the visitor session closed")
			if tc.left {
				assert.Zero(t, peerCount(a.a))
				return
			}
			p := onlyPeer(t, a.a)
			assert.Same(t, a.current(), p.rc, "the peer session is on the attached session")
			assert.False(t, p.idle)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "over the trunk")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a over the trunk")
		})
	}
}

// TestVisitTurn checks that the agent with the higher address opens no visit in
// its wait: it waits for the peer session of the other agent, or dials when its
// relay reaches the peer.
func TestVisitTurn(t *testing.T) {
	cases := []struct {
		name string
		ask  time.Duration // Interval at which b asks its relay again.
		// visit: a visits the relay of b while b waits.
		visit bool
		wait  time.Duration // Time that b waits. Zero is 10 s.
		// trunk: the peer session of b is one that b dialed over the trunk.
		trunk bool
		err   error
	}{
		{name: "relay reaches the peer at the next question", ask: 50 * time.Millisecond, trunk: true},
		{name: "peer visits", ask: time.Hour, visit: true},
		{name: "peer does not visit", ask: time.Hour, wait: 300 * time.Millisecond, err: errPeerVisits},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r1, r2, a, b, ea, eb := visitPair(t, agentOptions{mode: TransportPSP, visitCheck: time.Hour},
				agentOptions{mode: TransportPSP, visitAsk: tc.ask, visitWait: time.Minute})
			wait := tc.wait
			if wait == 0 {
				wait = 10 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), wait)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- b.a.connect(ctx, b.current(), ea.addr, visitAnswer(r1)) }()
			if tc.visit {
				actx, acancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer acancel()
				require.NoError(t, a.a.connect(actx, a.current(), eb.addr, visitAnswer(r2)))
			}
			err := <-done
			assert.Zero(t, visitCount(b.a), "visits of the agent with the higher address")
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Zero(t, peerCount(b.a))
				return
			}
			require.NoError(t, err)
			p := onlyPeer(t, b.a)
			assert.Same(t, b.current(), p.rc)
			assert.Equal(t, tc.trunk, p.dialer)
			want := 0
			if tc.visit {
				want = 1
			}
			assert.Equal(t, want, visitCount(a.a), "visits of the agent with the lower address")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a")
		})
	}
}

// TestNoRoute checks that a NoRoute with no home relay closes the peer sessions
// to the address, and that one with a home relay keeps them. The mesh path is
// up, so the relay answers REACH_TRUNK and no visit starts.
func TestNoRoute(t *testing.T) {
	cases := []struct {
		name   string
		home   bool
		closed bool
	}{
		{name: "no home relay", closed: true},
		{name: "home relay", home: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, r2, a, _, _, eb := visitPair(t, agentOptions{mode: TransportPSP}, agentOptions{mode: TransportPSP})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			p := onlyPeer(t, a.a)
			m := &dp.NoRoute{Vpc: a.current().ref, Address: eb.addr.String()}
			if tc.home {
				m.HomeRelay = r2.relayRef()
			}
			a.a.noRoute(a.current(), m)
			if tc.closed {
				assert.Zero(t, peerCount(a.a))
				assert.Error(t, p.qc.Context().Err(), "the peer session closed")
				return
			}
			require.Never(t, func() bool { return visitCount(a.a) != 0 || p.qc.Context().Err() != nil },
				300*time.Millisecond, 10*time.Millisecond, "the peer session stays, and no visit starts")
			assert.Same(t, p, onlyPeer(t, a.a))
			assert.False(t, a.a.holds.failing(eb.addr, time.Now()), "the answer REACH_TRUNK is no failure")
			// The answer REACH_TRUNK sets the path of the session to up again.
			a.a.setDown(a.current(), eb.addr, true)
			require.True(t, pathDown(a.a, p))
			a.a.visitAfterNoRoute(a.current(), eb.addr)
			assert.False(t, pathDown(a.a, p))
		})
	}
}

// TestVisitAfterCut cuts the mesh path between the relays of agents a and b, so
// that the relays give the answer REACH_VISIT themselves.
func TestVisitAfterCut(t *testing.T) {
	type step func(t *testing.T, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, conn *lossyConn)
	cases := []struct {
		name   string
		before bool // a and b have a peer session over the trunk before the cut.
		check  time.Duration
		wait   time.Duration // Wait of b before it visits. Zero is a wait with no end.
		run    step
	}{
		{
			// The NoRoute of relay-1 comes for the next peer frame of a, so the test gives it.
			name: "peer session before the cut, then the path comes back", before: true, check: 100 * time.Millisecond,
			run: func(t *testing.T, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				old := onlyPeer(t, a.a)
				heal := cutMesh(r1, r2)
				waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)
				waitReach(t, b, ea.addr, dp.Reach_REACH_VISIT)

				// b has the higher address, so it keeps its session and opens no visit.
				b.a.noRoute(b.current(), &dp.NoRoute{Vpc: b.current().ref, Address: ea.addr.String(), HomeRelay: r1.relayRef()})
				require.Never(t, func() bool { return visitCount(b.a) != 0 }, 300*time.Millisecond, 10*time.Millisecond)
				assert.Equal(t, 1, peerCount(b.a))

				a.a.noRoute(a.current(), &dp.NoRoute{Vpc: a.current().ref, Address: eb.addr.String(), HomeRelay: r2.relayRef()})
				var v *visit
				require.Eventually(t, func() bool {
					v = visitOf(a.a, r2)
					return v != nil && peerOn(a.a, v.rc, eb.addr) != nil
				}, 10*time.Second, 10*time.Millisecond, "peer session of a on its visitor session")
				assert.Error(t, old.qc.Context().Err(), "the session over the trunk closed")
				ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit")
				ping(t, b.stack, eb.addr, ea.addr, 9000, "to a on the visit")
				assert.Zero(t, visitCount(b.a))
				// relay-1 does not reach b, so the checks keep the visit.
				require.Never(t, func() bool { return visitOf(a.a, r2) != v }, 500*time.Millisecond, 10*time.Millisecond)

				heal()
				require.Eventually(t, func() bool {
					return visitCount(a.a) == 0 && peerOn(a.a, a.current(), eb.addr) != nil
				}, 30*time.Second, 20*time.Millisecond, "peer session of a on its attached session")
				assert.True(t, v.rc.ended(), "the visitor session closed")
				ping(t, a.stack, ea.addr, eb.addr, 9000, "to b over the trunk")
				ping(t, b.stack, eb.addr, ea.addr, 9000, "to a over the trunk")
			},
		},
		{
			name: "first packet after the cut",
			run: func(t *testing.T, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				cutMesh(r1, r2)
				waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)
				// The packets wait while the visit starts, and then go on it.
				require.NoError(t, sendOnce(a.stack, ea.addr, eb.addr, 9000, "first"))
				assert.Zero(t, a.a.Stats().HoldDrops)
				assert.Zero(t, unreachableIn(a), "ICMP errors")
				v := visitOf(a.a, r2)
				require.NotNil(t, v)
				assert.Same(t, v.rc, onlyPeer(t, a.a).rc)
				ping(t, b.stack, eb.addr, ea.addr, 9000, "to a on the visit")
				assert.Zero(t, visitCount(b.a))
			},
		},
		{
			name: "path probe fails, then passes",
			run: func(t *testing.T, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, conn *lossyConn) {
				cutMesh(r1, r2)
				waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)
				conn.limitProbes.Store(true)
				send(t, a.stack, ea.addr, eb.addr, 9000, "no data path")
				require.Eventually(t, func() bool { return unreachableIn(a) > 0 }, 10*time.Second, 10*time.Millisecond, "ICMP error")
				v := visitOf(a.a, r2)
				require.NotNil(t, v)
				assert.False(t, v.rc.data.Load())
				idle := onlyPeer(t, a.a)
				assert.True(t, idle.idle)
				assert.Same(t, v.rc, idle.rc)
				require.Equal(t, 1, peerCount(b.a), "the peer frames went to b")
				assert.Zero(t, rxCountOf(onlyPeer(t, b.a).bp).packets, "data packets of a at b")

				// The next open after the wait of the failure probes again.
				conn.limitProbes.Store(false)
				ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit")
				assert.Same(t, v, visitOf(a.a, r2), "the visit stays")
				assert.True(t, v.rc.data.Load())
				assert.Error(t, idle.qc.Context().Err(), "the session with no data path closed")
				p := peerOn(a.a, v.rc, eb.addr)
				require.NotNil(t, p)
				assert.False(t, p.idle)
			},
		},
		{
			// a sends nothing, so its relay gives it no NoRoute, and only b visits.
			name: "first packet of the higher address after the cut, then the path comes back", check: 100 * time.Millisecond, wait: 50 * time.Millisecond,
			run: func(t *testing.T, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				heal := cutMesh(r1, r2)
				waitReach(t, b, ea.addr, dp.Reach_REACH_VISIT)
				require.NoError(t, sendOnce(b.stack, eb.addr, ea.addr, 9000, "first"))
				assert.Zero(t, b.a.Stats().HoldDrops)
				v := visitOf(b.a, r1)
				require.NotNil(t, v)
				assert.Same(t, v.rc, onlyPeer(t, b.a).rc)
				p := onlyPeer(t, a.a)
				assert.Same(t, a.current(), p.rc, "a took the session on its attached session")
				assert.False(t, p.dialer)
				assert.Zero(t, visitCount(a.a), "a reaches b, so it does not visit")
				ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit of b")
				// relay-2 does not reach a, so the checks keep the visit.
				require.Never(t, func() bool { return visitOf(b.a, r1) != v }, 300*time.Millisecond, 10*time.Millisecond)

				heal()
				require.Eventually(t, func() bool {
					return visitCount(b.a) == 0 && peerOn(b.a, b.current(), ea.addr) != nil
				}, 30*time.Second, 20*time.Millisecond, "peer session of b on its attached session")
				assert.True(t, v.rc.ended(), "the visitor session closed")
				ping(t, b.stack, eb.addr, ea.addr, 9000, "to a over the trunk")
				ping(t, a.stack, ea.addr, eb.addr, 9000, "to b over the trunk")
			},
		},
		{
			// Each agent gets a NoRoute, and b does not wait, so the two agents visit.
			name: "peer session before the cut, the two agents visit", before: true, check: 100 * time.Millisecond, wait: time.Millisecond,
			run: func(t *testing.T, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				heal := cutMesh(r1, r2)
				waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)
				waitReach(t, b, ea.addr, dp.Reach_REACH_VISIT)
				b.a.noRoute(b.current(), &dp.NoRoute{Vpc: b.current().ref, Address: ea.addr.String(), HomeRelay: r1.relayRef()})
				a.a.noRoute(a.current(), &dp.NoRoute{Vpc: a.current().ref, Address: eb.addr.String(), HomeRelay: r2.relayRef()})
				oneVisit(t, a, b, ea, eb, heal)
			},
		},
		{
			// Only b sends data. A late packet of the old session can give a NoRoute to
			// a too: then the two agents visit, and the session on the visit of a stays.
			name: "peer session before the cut, only the higher address sends", check: 100 * time.Millisecond, wait: 50 * time.Millisecond,
			run: func(t *testing.T, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				require.NoError(t, a.a.Connect(ctx, eb.addr))
				old := onlyPeer(t, a.a)
				require.True(t, old.dialer)
				require.True(t, a.a.first(a.current(), old.subject, old.instance), "a is the first agent")
				heal := cutMesh(r1, r2)
				waitReach(t, b, ea.addr, dp.Reach_REACH_VISIT)
				// The test gives b the NoRoute for its packet on the old session.
				send(t, b.stack, eb.addr, ea.addr, 9000, "after the cut")
				b.a.noRoute(b.current(), &dp.NoRoute{Vpc: b.current().ref, Address: ea.addr.String(), HomeRelay: r1.relayRef()})
				oneVisit(t, a, b, ea, eb, heal)
			},
		},
		{
			// b is a visitor of relay-1 before the cut, so relay-1 sends the packets of a
			// for b to that session and gives a no NoRoute. Only its answer tells a of the cut.
			name: "peer session before the cut, the relay answer lets the visitor in",
			run: func(t *testing.T, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				require.NoError(t, a.a.Connect(ctx, eb.addr))
				old := onlyPeer(t, a.a)
				require.True(t, old.dialer)
				require.True(t, a.a.first(a.current(), old.subject, old.instance), "a is the first agent")
				v, err := b.a.visit(ctx, b.current(), r1.relayRef())
				require.NoError(t, err)
				defer b.a.release(v)
				cutMesh(r1, r2)
				waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)
				b.a.setDown(b.current(), ea.addr, true)
				require.False(t, pathDown(a.a, old), "a got no NoRoute")

				require.NoError(t, b.a.connect(ctx, v.rc, ea.addr, nil))
				assert.Error(t, old.qc.Context().Err(), "the old session closed")
				assert.Zero(t, visitCount(a.a))
				p := onlyPeer(t, a.a)
				assert.Same(t, a.current(), p.rc)
				assert.False(t, p.dialer)
				require.NotNil(t, peerOn(b.a, v.rc, ea.addr), "peer session of b on its visitor session")
				ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit of b")
				ping(t, b.stack, eb.addr, ea.addr, 9000, "to a on the visit of b")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := &lossyConn{}
			wait := tc.wait
			if wait == 0 {
				wait = time.Hour
			}
			r1, r2, a, b, ea, eb := visitPair(t, agentOptions{mode: TransportPSP, conn: conn, visitCheck: tc.check},
				agentOptions{mode: TransportPSP, visitCheck: tc.check, visitWait: wait})
			if tc.before {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				require.NoError(t, a.a.Connect(ctx, eb.addr))
				ping(t, a.stack, ea.addr, eb.addr, 9000, "before the cut")
			}
			tc.run(t, r1, r2, a, b, ea, eb, conn)
		})
	}
}

// TestVisitBoth checks the visit of the agent with the higher address, and that
// one peer session stays when each agent visits the relay of the other. The
// mesh path is up, so the relays take the visits as with a cut path.
func TestVisitBoth(t *testing.T) {
	type step func(t *testing.T, ctx context.Context, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, conn *lossyConn)
	cases := []struct {
		name string
		wait time.Duration // Wait of b before it visits.
		// onA: the session that stays is on the visit of a. Else it is on the visit of b.
		onA bool
		run step
	}{
		{
			name: "only the higher address visits", wait: 50 * time.Millisecond,
			run: func(t *testing.T, ctx context.Context, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				require.NoError(t, b.a.connect(ctx, b.current(), ea.addr, visitAnswer(r1)))
				assert.Zero(t, visitCount(a.a), "a sent nothing, so it does not visit")
				// a reaches b on its attached session, so the answer REACH_VISIT starts no visit.
				require.NoError(t, a.a.connectVisit(ctx, a.current(), eb.addr, r2.relayRef()))
				assert.Zero(t, visitCount(a.a))
			},
		},
		{
			name: "the lower address visits after the higher address", wait: 50 * time.Millisecond, onA: true,
			run: func(t *testing.T, ctx context.Context, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				require.NoError(t, b.a.connect(ctx, b.current(), ea.addr, visitAnswer(r1)))
				second := onlyPeer(t, b.a)
				_, err := dialOnVisit(t, ctx, a, r2, eb.addr)
				require.NoError(t, err)
				assert.Error(t, second.qc.Context().Err(), "the session on the visit of b closed")
			},
		},
		{
			name: "the higher address visits after the lower address", wait: time.Hour, onA: true,
			run: func(t *testing.T, ctx context.Context, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, _ *lossyConn) {
				require.NoError(t, a.a.connect(ctx, a.current(), eb.addr, visitAnswer(r2)))
				pa, pb := onlyPeer(t, a.a), onlyPeer(t, b.a)
				// a refuses the dial of b, and b uses the session of the visit of a.
				_, err := dialOnVisit(t, ctx, b, r1, ea.addr)
				require.NoError(t, err)
				require.Eventually(t, func() bool { return peerCount(a.a) == 1 && peerCount(b.a) == 1 }, 5*time.Second, 10*time.Millisecond)
				assert.Same(t, pa, onlyPeer(t, a.a))
				assert.Same(t, pb, onlyPeer(t, b.a))
			},
		},
		{
			// b waits with no end, so only the refused keys of a start its visit.
			name: "the visit of the lower address has no data path", wait: time.Hour,
			run: func(t *testing.T, ctx context.Context, r1, r2 *testRelay, a, b *testAgent, ea, eb attachEvent, conn *lossyConn) {
				done := make(chan error, 1)
				go func() { done <- b.a.connect(ctx, b.current(), ea.addr, visitAnswer(r1)) }()
				conn.limitProbes.Store(true)
				require.ErrorIs(t, a.a.connect(ctx, a.current(), eb.addr, visitAnswer(r2)), errVisitNoData)
				require.NoError(t, <-done)
				// b reaches a on its own visit now, so it does not wait again.
				require.NoError(t, b.a.connect(ctx, b.current(), ea.addr, visitAnswer(r1)))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := &lossyConn{}
			r1, r2, a, b, ea, eb := visitPair(t, agentOptions{mode: TransportPSP, conn: conn, visitCheck: time.Hour},
				agentOptions{mode: TransportPSP, visitCheck: time.Hour, visitAsk: time.Hour, visitWait: tc.wait})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tc.run(t, ctx, r1, r2, a, b, ea, eb, conn)

			// One peer session stays: on a visitor session of one agent, and on the
			// attached session of the other.
			visitor, taker, far := b, a, r1
			if tc.onA {
				visitor, taker, far = a, b, r2
			}
			require.Eventually(t, func() bool { return peerCount(a.a) == 1 && peerCount(b.a) == 1 }, 5*time.Second, 10*time.Millisecond)
			v := visitOf(visitor.a, far)
			require.NotNil(t, v)
			pv, pt := onlyPeer(t, visitor.a), onlyPeer(t, taker.a)
			assert.Same(t, v.rc, pv.rc)
			assert.True(t, pv.dialer)
			assert.Same(t, taker.current(), pt.rc)
			assert.False(t, pt.dialer)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a")
			assert.Same(t, pv, onlyPeer(t, visitor.a), "the session stays")

			// A check ends the visit that no peer uses. A check of the other visit
			// moves its peer back: the home relay reaches it over the trunk.
			for _, ta := range []*testAgent{taker, visitor} {
				ta.a.mu.Lock()
				var vs []*visit
				for _, v := range ta.a.visits {
					vs = append(vs, v)
				}
				ta.a.mu.Unlock()
				for _, v := range vs {
					require.True(t, ta.a.checkVisit(v), "the visit ended")
				}
				assert.Zero(t, visitCount(ta.a))
				if ta == taker {
					assert.Same(t, pt, onlyPeer(t, taker.a), "the check of a visit with no peer changes no session")
				}
			}
			require.Eventually(t, func() bool { return peerCount(a.a) == 1 && peerCount(b.a) == 1 }, 5*time.Second, 10*time.Millisecond)
			assert.Same(t, visitor.current(), onlyPeer(t, visitor.a).rc, "the peer session is on the attached session")
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b over the trunk")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a over the trunk")
		})
	}
}

// TestVisitDuplicate checks the duplicate rule for the dial of a visitor. a is
// the first agent and dialed the old session, so it refuses b while the path is up.
func TestVisitDuplicate(t *testing.T) {
	cases := []struct {
		name string
		down bool // The agents know that the path of the old session is down.
	}{
		{name: "path up, the old session stays"},
		{name: "path down, the new session replaces it", down: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r1, _, a, b, ea, eb := visitPair(t, agentOptions{mode: TransportPSP, visitCheck: time.Hour}, agentOptions{mode: TransportPSP, visitCheck: time.Hour})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			require.Eventually(t, func() bool { return peerCount(b.a) == 1 }, 5*time.Second, 10*time.Millisecond)
			oldA, oldB := onlyPeer(t, a.a), onlyPeer(t, b.a)
			require.True(t, oldA.dialer)
			require.True(t, a.a.first(a.current(), oldA.subject, oldA.instance), "a is the first agent")
			if tc.down {
				a.a.setDown(a.current(), eb.addr, true)
				b.a.setDown(b.current(), ea.addr, true)
			}

			v, err := dialOnVisit(t, ctx, b, r1, ea.addr)
			require.NoError(t, err)
			require.Eventually(t, func() bool { return peerCount(a.a) == 1 && peerCount(b.a) == 1 }, 5*time.Second, 10*time.Millisecond)
			pa, pb := onlyPeer(t, a.a), onlyPeer(t, b.a)
			if !tc.down {
				assert.Same(t, oldA, pa)
				assert.Same(t, oldB, pb)
				assert.NoError(t, oldA.qc.Context().Err(), "the old session is open")
				return
			}
			assert.Error(t, oldA.qc.Context().Err(), "the old session closed")
			assert.Same(t, a.current(), pa.rc)
			assert.False(t, pa.dialer)
			assert.Same(t, v.rc, pb.rc)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to b on the visit of b")
			ping(t, b.stack, eb.addr, ea.addr, 9000, "to a on the visit of b")
		})
	}
}
