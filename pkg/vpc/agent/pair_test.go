// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

// pairWait is the most time for a pair to open or to end.
const pairWait = 15 * time.Second

// pairsOf returns the pairs of ta in its last snapshot.
func pairsOf(ta *testAgent) []pairSnap { return ta.a.snap.Load().pairs }

// openPairs waits until ta has n pairs, all open, and returns them.
func openPairs(t *testing.T, ta *testAgent, n int, msg string) []pairSnap {
	t.Helper()
	var got []pairSnap
	require.Eventually(t, func() bool {
		got = pairsOf(ta)
		return len(got) == n && !slices.ContainsFunc(got, func(s pairSnap) bool { return !s.open })
	}, pairWait, 20*time.Millisecond, "%s: %d open pairs", msg, n)
	return got
}

// noPairs waits until ta has no pairs.
func noPairs(t *testing.T, ta *testAgent, d time.Duration, msg string) {
	t.Helper()
	for end := time.Now().Add(d); len(pairsOf(ta)) > 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("%s: pairs stay: %+v", msg, pairsOf(ta))
		}
	}
}

// pairID is a pair and its channel, which do not change for the life of the pair.
type pairID struct {
	flow flow
	open bool
	inst uint64
}

// pairIDs returns the pairs of ta in its last snapshot.
func pairIDs(ta *testAgent) []pairID {
	var out []pairID
	for _, s := range pairsOf(ta) {
		out = append(out, pairID{s.flow, s.open, s.inst})
	}
	return out
}

// stays checks that the pairs of ta do not change for d.
func stays(t *testing.T, ta *testAgent, d time.Duration) {
	t.Helper()
	want := pairIDs(ta)
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		require.Equal(t, want, pairIDs(ta), "the pairs changed")
	}
}

// channelOf returns the base address of the channel prefix of addr.
func channelOf(addr netip.Addr) netip.Addr {
	return relay.OverlayAddr(netip.PrefixFrom(addr, 96).Masked())
}

// TestPairOpen opens a channel between two agents through the relays. The pairs go direct after
// the Keys calls, and then the relays take no data packet of the two agents.
func TestPairOpen(t *testing.T) {
	cases := []struct {
		name  string
		noPSP bool // The sessions are in QUIC mode.
		two   bool // b has a session on each of two relays in a mesh.
	}{
		{name: "PSP mode"},
		{name: "QUIC mode", noPSP: true},
		{name: "two sessions", two: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var w *world
			var r1, r2 *testRelay
			if tc.two {
				w, r1, r2 = meshRelays(t)
			} else {
				w = newWorld(t)
				r1 = w.relay(t, "relay-1")
			}
			a := w.agent(t, "a", r1, agentOptions{direct: true, noPSP: tc.noPSP})
			ea := a.attached(t)
			bOpts := agentOptions{direct: true, noPSP: tc.noPSP}
			if tc.two {
				bOpts.sessions, bOpts.relays = 2, r1.refs(r2)
			}
			b := w.agent(t, "b", r1, bOpts)
			eb := []attachEvent{b.attached(t)}
			if tc.two {
				eb = append(eb, b.attached(t))
			}
			for _, e := range eb {
				echo(t, b.stack, e.addr, 9000)
			}
			ping(t, a.stack, ea.addr, eb[0].addr, 9000, "a to b")

			var bList []netip.Prefix
			for _, e := range eb {
				bList = append(bList, e.prefixes[0])
			}
			slices.SortFunc(bList, netip.Prefix.Compare)
			start := time.Now()
			da, db := directPair(t, a, "a"), directPair(t, b, "b")
			t.Logf("direct after %v", time.Since(start).Round(time.Millisecond))
			assert.Equal(t, bList, da.Prefixes, "the pair of a holds each prefix of b")
			assert.Equal(t, []netip.Prefix{ea.prefixes[0]}, db.Prefixes, "the pair of b holds the prefix of a")
			assert.Equal(t, "b", da.Peer)
			assert.Equal(t, instanceString(b.a.instance), da.Instance)
			assert.Empty(t, da.Reason)
			assert.Len(t, da.Key, 64)
			assert.Equal(t, b.socket(), da.Address, "the agent socket of b")
			assert.Positive(t, da.RTT)
			assert.True(t, da.Dialed, "a dialed")
			assert.Equal(t, "a", db.Peer)
			assert.Equal(t, instanceString(a.a.instance), db.Instance)
			assert.Equal(t, a.socket(), db.Address, "the agent socket of a")
			assert.False(t, db.Dialed, "b accepted")
			assert.NotEqual(t, da.Key, db.Key, "each side has the key of the other")

			// A packet sent before the installs can still be on the relay path.
			time.Sleep(time.Second)
			relays := []*testRelay{r1}
			if tc.two {
				relays = append(relays, r2)
			}
			for _, e := range eb {
				flat(t, a, ea.addr, e.addr, relays, 2*time.Second)
			}
			// The pair stays: no end and no second pair while the channel is open.
			want := pairIDs(b)
			stays(t, a, 2*time.Second)
			assert.Equal(t, want, pairIDs(b), "the pairs of b changed")
		})
	}
}

// refs returns the relay refs of r and of others, in order.
func (r *testRelay) refs(others ...*testRelay) []identity.Relay {
	out := []identity.Relay{r.ref()}
	for _, o := range others {
		out = append(out, o.ref())
	}
	return out
}

// TestPairBothDial makes two agents dial each other at one time on one flow. Each side keeps one
// pair with one channel.
func TestPairBothDial(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	blockA, blockB := &blockConn{relay: r.psp}, &blockConn{relay: r.psp}
	a := w.agent(t, "a", r, agentOptions{direct: true, block: blockA})
	b := w.agent(t, "b", r, agentOptions{direct: true, block: blockB})
	ea, eb := a.attached(t), b.attached(t)
	// No packet gets to the relay, so the Initials of each dial wait for a retry.
	blockA.out.Store(true)
	blockB.out.Store(true)
	send(t, a.stack, ea.addr, eb.addr, 9000, "a to b")
	send(t, b.stack, eb.addr, ea.addr, 9000, "b to a")
	require.Eventually(t, func() bool { return len(pairsOf(a)) == 1 && len(pairsOf(b)) == 1 }, 5*time.Second, 10*time.Millisecond,
		"each side starts a pair")
	time.Sleep(1500 * time.Millisecond)
	blockA.out.Store(false)
	blockB.out.Store(false)

	pa := openPairs(t, a, 1, "a")
	pb := openPairs(t, b, 1, "b")
	assert.Equal(t, flow{own: ea.addr, peer: channelOf(eb.addr)}, pa[0].flow)
	assert.Equal(t, flow{own: eb.addr, peer: channelOf(ea.addr)}, pb[0].flow)
	assert.Equal(t, b.a.instance, pa[0].inst)
	assert.Equal(t, a.a.instance, pb[0].inst)
	// The channel is the connection whose QUIC client has the lower address.
	aLower := ea.addr.Less(eb.addr)
	da, db := a.a.Status().Direct, b.a.Status().Direct
	require.Len(t, da, 1)
	require.Len(t, db, 1)
	assert.Equal(t, aLower, da[0].Dialed, "a is the QUIC client of the channel")
	assert.Equal(t, !aLower, db[0].Dialed, "b is the QUIC client of the channel")
	want := pairIDs(b)
	stays(t, a, 2*time.Second)
	assert.Equal(t, want, pairIDs(b), "the pairs of b changed")
}

// TestPairDuplicate opens two channels from a to the two sessions of b at one time. Each side keeps
// one pair on one channel, and the other pair ends.
func TestPairDuplicate(t *testing.T) {
	t.Parallel()
	w, r1, r2 := meshRelays(t)
	block := &blockConn{relay: r1.psp}
	a := w.agent(t, "a", r1, agentOptions{direct: true, block: block})
	ea := a.attached(t)
	b := w.agent(t, "b", r1, agentOptions{direct: true, sessions: 2, relays: r1.refs(r2)})
	b1, b2 := b.attached(t), b.attached(t)
	block.out.Store(true)
	// The open deadline of each pair is after this.
	deadline := time.Now().Add(defaultPairOpenTimeout - 5*time.Second)
	send(t, a.stack, ea.addr, b1.addr, 9000, "a to b1")
	send(t, a.stack, ea.addr, b2.addr, 9000, "a to b2")
	require.Eventually(t, func() bool { return len(pairsOf(a)) == 2 }, 5*time.Second, 10*time.Millisecond, "a starts two pairs")
	time.Sleep(1500 * time.Millisecond)
	block.out.Store(false)

	// When both pairs have a connection, the lower address of b wins. A pair with no connection
	// ends after the open of the other one, so either address can win.
	var pa, pb []pairSnap
	require.Eventually(t, func() bool {
		pa, pb = pairsOf(a), pairsOf(b)
		return len(pa) == 1 && pa[0].open && len(pb) == 1 && pb[0].open && pb[0].flow.own == pa[0].flow.peer
	}, time.Until(deadline), 20*time.Millisecond, "each side has one pair, open on one channel, before the open deadline")
	assert.Contains(t, []netip.Addr{channelOf(b1.addr), channelOf(b2.addr)}, pa[0].flow.peer)
	assert.Equal(t, b.a.instance, pa[0].inst)
	openIDs := func(ta *testAgent) []pairID {
		return slices.DeleteFunc(pairIDs(ta), func(p pairID) bool { return !p.open })
	}
	ida, idb := []pairID{{pa[0].flow, true, pa[0].inst}}, []pairID{{pb[0].flow, true, pb[0].inst}}
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		require.Equal(t, ida, openIDs(a), "the open pair of a changed")
		require.Equal(t, idb, openIDs(b), "the open pair of b changed")
	}
}

// TestPairHeld starts a pair to the second address of b before the Hello of the pair to the first
// address, and the mesh drops its Initials. That Hello lists the second address, so the second pair
// ends at once, not at the open deadline, and a shows one pair for b.
func TestPairHeld(t *testing.T) {
	t.Parallel()
	w, r1, r2, cut := cutRelays(t)
	a := w.agent(t, "a", r1, agentOptions{direct: true})
	ea := a.attached(t)
	b := w.agent(t, "b", r1, agentOptions{direct: true, sessions: 2, relays: r1.refs(r2)})
	b1, b2 := b.attached(t), b.attached(t)
	_, slot2 := slotAddr(2)
	if slotOf(b1.addr) == slot2 {
		b1, b2 = b2, b1
	}
	require.Equal(t, slot2, slotOf(b2.addr), "b has a session on relay-2")
	require.NotEqual(t, slot2, slotOf(b1.addr), "b has a session on relay-1")
	echo(t, b.stack, b1.addr, 9000)
	echo(t, b.stack, b2.addr, 9000)
	a.hasRoutes(t, slot2)

	// The packets to b2 cross the mesh, which drops them. The mesh stays up for its idle timeout.
	cut.drop(true)
	send(t, a.stack, ea.addr, b2.addr, 9000, "a to b2")
	require.Eventually(t, func() bool { return len(pairsOf(a)) == 1 }, 5*time.Second, 10*time.Millisecond, "a starts a pair to b2")
	ping(t, a.stack, ea.addr, b1.addr, 9000, "a to b1")
	var pa []pairSnap
	require.Eventually(t, func() bool {
		pa = pairsOf(a)
		return len(pa) == 1 && pa[0].open
	}, 5*time.Second, 10*time.Millisecond, "the pair to b2 ends at the open of the pair to b1")
	assert.Equal(t, channelOf(b1.addr), pa[0].flow.peer)
	cut.drop(false)

	want := []netip.Prefix{b1.prefixes[0], b2.prefixes[0]}
	slices.SortFunc(want, netip.Prefix.Compare)
	d := directPair(t, a, "a")
	assert.Equal(t, want, d.Prefixes, "the pair of a holds each prefix of b")
	assert.Equal(t, instanceString(b.a.instance), d.Instance)
	openPairs(t, b, 1, "b")
}

// TestPairClaims gives two peers of a one prefix: the first pair holds it until it ends. The path to
// the first peer is blocked, because its route would take the channel of the second one too.
func TestPairClaims(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.slots = map[string]int{"relay-1": 1, "relay-2": 2}
	r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
	udpX := loopback(t)
	block := &blockConn{relay: udpX.LocalAddr().String()}
	block.out.Store(true)
	block.in.Store(true)
	opts, first := twoSessions(t, r1, r2, agentOptions{direct: true, block: block})
	a := w.agent(t, "a", r2, opts)
	a2 := first(a)
	a1 := a.attached(t).addr
	// x is on relay-2 with the primary session of a.
	x := w.agent(t, "x", r2, agentOptions{direct: true, udp: udpX})
	ex := x.attached(t)
	echo(t, x.stack, ex.addr, 9000)
	ping(t, a.stack, a2, ex.addr, 9000, "a to x")
	openPairs(t, a, 1, "a with x")
	dx := a.a.Status().Direct
	require.Len(t, dx, 1)
	assert.Equal(t, []netip.Prefix{ex.prefixes[0]}, dx[0].Prefixes, "the pair with x holds its prefix")

	// y is on relay-1, which has no mesh, with the prefix of x.
	w.addrs.fix("y", ex.prefixes[0])
	y := w.agent(t, "y", r1, agentOptions{direct: true})
	ey := y.attached(t)
	require.Equal(t, ex.prefixes, ey.prefixes)
	send(t, y.stack, ey.addr, a1, 9000, "y to a")
	openPairs(t, a, 2, "a with x and y")
	byInst := func() map[string]DirectStatus {
		out := map[string]DirectStatus{}
		for _, d := range a.a.Status().Direct {
			out[d.Instance] = d
		}
		return out
	}
	// The pair with y goes direct, and only the first claim has the route.
	require.Eventually(t, func() bool { return byInst()[instanceString(y.a.instance)].State == DirectDirect }, pairWait, 20*time.Millisecond,
		"the pair with y goes direct")
	m := byInst()
	assert.NotEqual(t, DirectDirect, m[instanceString(x.a.instance)].State, "the path to x is blocked")
	assert.Equal(t, []netip.Prefix{ex.prefixes[0]}, m[instanceString(x.a.instance)].Prefixes, "the first claim holds")
	assert.Empty(t, m[instanceString(y.a.instance)].Prefixes, "the second claim waits")
	// relay-1 takes the data from a2 to the prefix to y. The second claim has no route, so the data
	// goes on the relay route.
	echo(t, y.stack, ey.addr, 9000)
	onRelay(t, a, a2, ey.addr, []*testRelay{r1, r2}, "a to y while x holds the prefix")

	x.stop()
	require.Eventually(t, func() bool {
		d := a.a.Status().Direct
		return len(d) == 1 && d[0].Instance == instanceString(y.a.instance) && d[0].State == DirectDirect && slices.Equal(d[0].Prefixes, ex.prefixes[:1])
	}, pairWait, 20*time.Millisecond, "the pair with y holds the prefix after the end of x")
	// The data to the prefix goes direct to y now, from 1 s after the new route.
	time.Sleep(time.Second)
	flat(t, a, a2, ey.addr, []*testRelay{r1, r2}, 2*time.Second)
}

// TestPairEnd stops the peer of a pair, and checks that the pair of a ends.
func TestPairEnd(t *testing.T) {
	t.Parallel()
	w, r1, r2 := meshRelays(t)
	a := w.agent(t, "a", r1, agentOptions{direct: true})
	b := w.agent(t, "b", r2, agentOptions{direct: true})
	ea, eb := a.attached(t), b.attached(t)
	echo(t, b.stack, eb.addr, 9000)
	ping(t, a.stack, ea.addr, eb.addr, 9000, "a to b")
	openPairs(t, a, 1, "a")
	openPairs(t, b, 1, "b")

	b.stop()
	// A late packet to b can start a new pair, which does not open.
	require.Eventually(t, func() bool {
		return !slices.ContainsFunc(pairsOf(a), func(s pairSnap) bool { return s.open })
	}, 5*time.Second, 20*time.Millisecond, "the pair of a ends")
}

// TestPairOpenTimeout dials a peer that has direct paths off. The pair shows the reason when the
// dial gets no answer, and ends at the open deadline.
func TestPairOpenTimeout(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{direct: true, pairOpen: 8 * time.Second})
	b := w.agent(t, "b", r, agentOptions{})
	ea, eb := a.attached(t), b.attached(t)
	echo(t, b.stack, eb.addr, 9000)
	ping(t, a.stack, ea.addr, eb.addr, 9000, "a to b")
	require.Eventually(t, func() bool {
		d := a.a.Status().Direct
		return len(d) == 1 && d[0].Reason == ReasonNoDirectPaths
	}, 10*time.Second, 20*time.Millisecond, "the pair shows that b has no direct paths")
	d := a.a.Status().Direct[0]
	assert.Equal(t, DirectRelay, d.State, "the data to b goes on the relay route")
	assert.Empty(t, d.Peer)
	assert.Empty(t, d.Key, "the channel is not open")
	assert.Equal(t, []netip.Prefix{eb.prefixes[0]}, d.Prefixes, "the channel prefix of b")
	noPairs(t, a, 5*time.Second, "a after the open deadline")
	assert.Empty(t, pairsOf(b), "b has no pairs")

	// New data to b starts a new pair with no reason.
	ping(t, a.stack, ea.addr, eb.addr, 9000, "a to b again")
	require.Eventually(t, func() bool {
		d := a.a.Status().Direct
		return len(d) == 1 && d[0].Reason == ""
	}, 2*time.Second, 20*time.Millisecond, "a new pair")
}

// TestPairIdentity opens channels from a to two peers with one agent name. Two keys give two pairs,
// and one key with two instances gives two pairs.
func TestPairIdentity(t *testing.T) {
	cases := []struct {
		name    string
		oneFile bool // The peers have one identity file, so they have one key.
	}{
		{name: "two keys"},
		{name: "one identity file", oneFile: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{direct: true})
			ea := a.attached(t)
			opts := agentOptions{direct: true, identity: "b"}
			if tc.oneFile {
				opts.identityFile, opts.identityPath = true, filepath.Join(t.TempDir(), "identity.json")
			}
			b1 := w.agent(t, "b1", r, opts)
			e1 := b1.attached(t)
			b2 := w.agent(t, "b2", r, opts)
			e2 := b2.attached(t)
			echo(t, b1.stack, e1.addr, 9000)
			echo(t, b2.stack, e2.addr, 9000)
			ping(t, a.stack, ea.addr, e1.addr, 9000, "a to b1")
			ping(t, a.stack, ea.addr, e2.addr, 9000, "a to b2")
			openPairs(t, a, 2, "a")
			d := a.a.Status().Direct
			require.Len(t, d, 2)
			assert.Equal(t, "b", d[0].Peer)
			assert.Equal(t, "b", d[1].Peer)
			assert.ElementsMatch(t, []string{instanceString(b1.a.instance), instanceString(b2.a.instance)}, []string{d[0].Instance, d[1].Instance})
			if tc.oneFile {
				assert.Equal(t, d[0].Key, d[1].Key, "one key")
			} else {
				assert.NotEqual(t, d[0].Key, d[1].Key, "two keys")
			}
		})
	}
}
