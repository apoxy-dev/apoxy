// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// entrySpec is one entry of a selection test: the attachment id of an agent
// process on a relay.
type entrySpec struct {
	agent    string
	instance uint64
	relay    string
	id       string
	gen      uint64 // Generation at the attach.
	rank     uint32
	state    dp.AnnouncerState
	// hold is the time from the selection to the end of the hold time of the
	// entry. Zero is no hold time, and a time below zero is one that ended.
	hold time.Duration
}

// selectTime is the time of the selection in a test of selectOrder.
var selectTime = time.Unix(1_700_000_000, 0)

// entryHash is the hash that the protocol gives for an agent process with the
// name "base" and a prefix. It uses no code of the relay.
func entryHash(agent string, instance uint64, p netip.Prefix) []byte {
	b := append([]byte(agentID(vpcA, agent)), 0)
	b = append(append(b, "base"...), 0)
	b = binary.BigEndian.AppendUint64(b, instance)
	sum := sha256.Sum256(append(b, p.String()...))
	return sum[:]
}

// agentsByHash returns the agent names in the order of their hash for p, each
// with the instance 0: the selection takes the first one before the others.
func agentsByHash(p netip.Prefix, names ...string) []string {
	slices.SortFunc(names, func(a, b string) int { return bytes.Compare(entryHash(a, 0, p), entryHash(b, 0, p)) })
	return names
}

// entry returns the announcer of spec for the prefix p.
func (spec entrySpec) entry(p netip.Prefix) *announcer {
	s := &Session{id: Identity{VPC: vpcA, ID: agentID(vpcA, spec.agent)}, name: "base", instance: spec.instance, home: spec.relay}
	var activeFrom time.Time
	if spec.hold != 0 {
		activeFrom = selectTime.Add(spec.hold)
	}
	c := &candidate{agent: s.agent(), relay: spec.relay, attached: spec.gen, rank: spec.rank, state: spec.state, activeFrom: activeFrom}
	return newAnnouncer(target{s: s, origin: spec.id}, c, p)
}

// orderNames returns "attachment@relay" for each entry of order.
func orderNames(order []*announcer) []string {
	names := make([]string, len(order))
	for i, e := range order {
		names[i] = e.origin + "@" + e.relay
	}
	return names
}

// permutations calls f with each order of the n indexes 0 to n-1.
func permutations(n int, f func([]int)) {
	var walk func(order []int)
	walk = func(order []int) {
		if len(order) == n {
			f(order)
			return
		}
		for i := range n {
			if !slices.Contains(order, i) {
				walk(append(order, i))
			}
		}
	}
	walk(make([]int, 0, n))
}

// TestSelectOrder checks the selection for one prefix. Each case gets the same
// result for each order in which the entries come.
func TestSelectOrder(t *testing.T) {
	p := netip.MustParsePrefix(prefixR)
	// The selection takes the agent a before b, b before c, and c before d.
	ag := agentsByHash(p, "one", "two", "three", "four")
	a, b, c, d := ag[0], ag[1], ag[2], ag[3]
	cases := []struct {
		name    string
		entries []entrySpec
		want    []string
	}{
		{
			name:    "one entry",
			entries: []entrySpec{{agent: a, relay: "relay-a", id: "x"}},
			want:    []string{"x@relay-a"},
		},
		{
			// The generation and the relay name do not decide between two agents.
			name: "three agents: the lower hash comes first",
			entries: []entrySpec{
				{agent: c, relay: "relay-a", id: "x", gen: 30},
				{agent: a, relay: "relay-c", id: "y", gen: 10, rank: 9},
				{agent: b, relay: "relay-b", id: "z", gen: 20},
			},
			want: []string{"y@relay-c", "z@relay-b", "x@relay-a"},
		},
		{
			name: "draining, suspect and a state from a later revision come last",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "w", state: 7},
				{agent: b, relay: "relay-a", id: "x", state: stateSuspect},
				{agent: c, relay: "relay-a", id: "y", state: stateDraining},
				{agent: d, relay: "relay-a", id: "z", state: stateNormal},
			},
			want: []string{"z@relay-a", "y@relay-a", "x@relay-a", "w@relay-a"},
		},
		{
			name: "reconnect on one relay: the higher generation replaces the entry",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "x", gen: 10},
				{agent: a, relay: "relay-a", id: "y", gen: 11},
				{agent: b, relay: "relay-a", id: "z"},
			},
			want: []string{"y@relay-a", "z@relay-a"},
		},
		{
			name: "reconnect on one relay: the older entry does not come back as a standby announcer",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "x", gen: 12, state: stateSuspect},
				{agent: a, relay: "relay-a", id: "y", gen: 11},
			},
			want: []string{"x@relay-a"},
		},
		{
			name: "two attachments of one connection at one generation: the lower ID stays",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "y", gen: 10},
				{agent: a, relay: "relay-a", id: "x", gen: 10},
			},
			want: []string{"x@relay-a"},
		},
		{
			// The draining state shows the two entries in a known order.
			name: "two instances of one agent name are two announcers",
			entries: []entrySpec{
				{agent: a, instance: 1, relay: "relay-a", id: "x", gen: 10, state: stateDraining},
				{agent: a, instance: 2, relay: "relay-a", id: "y", gen: 11},
			},
			want: []string{"y@relay-a", "x@relay-a"},
		},
		{
			name: "one agent on two relays: the lower rank is active, and the other is standby",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "x", gen: 20, rank: 1},
				{agent: a, relay: "relay-b", id: "y", gen: 10, rank: 0},
			},
			want: []string{"y@relay-b", "x@relay-a"},
		},
		{
			name: "one agent on two relays with equal ranks: the lower relay name is active",
			entries: []entrySpec{
				{agent: a, relay: "relay-b", id: "x", gen: 20},
				{agent: a, relay: "relay-a", id: "y", gen: 10},
			},
			want: []string{"y@relay-a", "x@relay-b"},
		},
		{
			name: "active connection is suspect: the other connection of the agent comes before another agent",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "x", rank: 0, state: stateSuspect},
				{agent: a, relay: "relay-b", id: "y", rank: 1},
				{agent: b, relay: "relay-c", id: "z"},
			},
			want: []string{"y@relay-b", "z@relay-c", "x@relay-a"},
		},
		{
			name: "active connection is draining: the other connection of the agent comes before another agent",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "x", rank: 0, state: stateDraining},
				{agent: a, relay: "relay-b", id: "y", rank: 1},
				{agent: b, relay: "relay-c", id: "z"},
			},
			want: []string{"y@relay-b", "z@relay-c", "x@relay-a"},
		},
		{
			name: "active connection is gone: the other connection of the agent comes before another agent",
			entries: []entrySpec{
				{agent: a, relay: "relay-b", id: "y", rank: 1},
				{agent: b, relay: "relay-c", id: "z"},
			},
			want: []string{"y@relay-b", "z@relay-c"},
		},
		{
			name: "two agents, each on two relays: the agent, then the rank, then the relay name",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "w", rank: 1},
				{agent: a, relay: "relay-b", id: "x", rank: 0},
				{agent: b, relay: "relay-b", id: "y"},
				{agent: b, relay: "relay-a", id: "z"},
			},
			want: []string{"x@relay-b", "w@relay-a", "z@relay-a", "y@relay-b"},
		},
		{
			name: "normal entry in its hold time comes after each normal entry out of it",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "x", hold: time.Second},
				{agent: b, relay: "relay-a", id: "y", hold: -time.Second},
				{agent: c, relay: "relay-a", id: "z"},
			},
			want: []string{"y@relay-a", "z@relay-a", "x@relay-a"},
		},
		{
			name: "each normal entry is in its hold time: the one that ends first comes first",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "x", hold: 2 * time.Second},
				{agent: b, relay: "relay-a", id: "y", hold: time.Second},
				{agent: c, relay: "relay-a", id: "z", hold: 3 * time.Second},
			},
			want: []string{"y@relay-a", "x@relay-a", "z@relay-a"},
		},
		{
			name: "each normal entry is in its hold time, with one end: the order is that with no hold time",
			entries: []entrySpec{
				{agent: b, relay: "relay-a", id: "y", hold: time.Second},
				{agent: a, relay: "relay-a", id: "x", hold: time.Second},
				{agent: c, relay: "relay-a", id: "z", state: stateDraining},
			},
			want: []string{"x@relay-a", "y@relay-a", "z@relay-a"},
		},
		{
			name: "entry in its hold time comes before a draining and a suspect entry",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "x", state: stateDraining},
				{agent: b, relay: "relay-a", id: "y", state: stateSuspect},
				{agent: c, relay: "relay-a", id: "z", hold: time.Second},
			},
			want: []string{"z@relay-a", "x@relay-a", "y@relay-a"},
		},
		{
			name: "draining and suspect entries have no hold time",
			entries: []entrySpec{
				{agent: a, relay: "relay-a", id: "w", state: stateDraining, hold: time.Second},
				{agent: b, relay: "relay-a", id: "x", state: stateDraining},
				{agent: a, relay: "relay-b", id: "y", state: stateSuspect, hold: time.Second},
				{agent: b, relay: "relay-b", id: "z", state: stateSuspect},
			},
			want: []string{"w@relay-a", "x@relay-a", "y@relay-b", "z@relay-b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			permutations(len(tc.entries), func(order []int) {
				entries := make([]*announcer, len(order))
				for i, n := range order {
					entries[i] = tc.entries[n].entry(p)
				}
				assert.Equal(t, tc.want, orderNames(selectOrder(entries, selectTime)), "entries in the order %v", order)
			})
		})
	}
}

// TestSelectOrderByHash checks that the hash of agent and prefix orders two
// agents, and that the connections of one agent stay together.
func TestSelectOrderByHash(t *testing.T) {
	first := map[string]int{}
	for n := range 64 {
		p := netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", n))
		specs := []entrySpec{
			{agent: "a", instance: 1, relay: "relay-a", id: "a1", rank: 1},
			{agent: "b", instance: 2, relay: "relay-a", id: "b1"},
			{agent: "a", instance: 1, relay: "relay-b", id: "a0"},
			{agent: "b", instance: 2, relay: "relay-b", id: "b2"},
		}
		want := []string{"a0@relay-b", "a1@relay-a", "b1@relay-a", "b2@relay-b"}
		if bytes.Compare(entryHash("b", 2, p), entryHash("a", 1, p)) < 0 {
			want = []string{"b1@relay-a", "b2@relay-b", "a0@relay-b", "a1@relay-a"}
		}
		permutations(len(specs), func(order []int) {
			entries := make([]*announcer, len(order))
			for i, k := range order {
				entries[i] = specs[k].entry(p)
			}
			require.Equal(t, want, orderNames(selectOrder(entries, selectTime)), "prefix %s, entries in the order %v", p, order)
		})
		first[want[0][:1]]++
	}
	assert.NotZero(t, first["a"], "prefixes with the agent a first")
	assert.NotZero(t, first["b"], "prefixes with the agent b first")
}

// entriesOf returns the entries of prefix in vpcA of r, as "attachment@relay"
// in the order of selection.
func entriesOf(r *Router, prefix string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return orderNames(r.domains[vpcA].orderOf(netip.MustParsePrefix(prefix)))
}

// TestAnnouncerFromPresence checks the entry that the relay makes for an
// attachment of another relay: with the fields of this revision, and for a
// member from before it, which sends none of them.
func TestAnnouncerFromPresence(t *testing.T) {
	cases := []struct {
		name  string
		entry *dp.Presence
		want  candidate
	}{
		{
			name:  "member from before the revision: instance 0, rank 0, normal state",
			entry: remoteEntry("x", 10, prefixR),
			want:  candidate{agent: agentKey{id: laptop, name: "base"}, attached: 10, state: stateNormal},
		},
		{
			name: "instance, rank and state",
			entry: func() *dp.Presence {
				e := ranked(draining(remoteEntry("x", 10, prefixR)), 2)
				e.Instance = 77
				return e
			}(),
			want: candidate{agent: agentKey{id: laptop, name: "base", instance: 77}, attached: 10, rank: 2, state: stateDraining},
		},
		{
			name: "entry with a new state: the generation at the attach stays",
			entry: func() *dp.Presence {
				e := draining(remoteEntry("x", 30, prefixR))
				e.Attached = 10
				return e
			}(),
			want: candidate{agent: agentKey{id: laptop, name: "base"}, attached: 10, state: stateDraining},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				// The relay knows a VPC only with a session of it.
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				w.send("relay-a", tc.entry)
				w.r.mu.RLock()
				defer w.r.mu.RUnlock()
				got := w.r.domains[vpcA].routes[netip.MustParsePrefix(prefixR)].active()
				assert.Equal(t, "relay-a", got.relay)
				assert.Equal(t, tc.want.agent, got.agent)
				assert.Equal(t, tc.want.attached, got.attached)
				assert.Equal(t, tc.want.rank, got.rank)
				assert.Equal(t, tc.want.state, got.state)
			})
		})
	}
}

// TestReconnectThenStateChange checks that a later state change of the old
// attachment does not bring it back in the selection after a reconnect.
func TestReconnectThenStateChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newRouteWorld(t, NewRouter(nil, Config{}))
		w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
		suspectAt := func(gen, attached uint64) *dp.Presence {
			e := remoteEntry("x", gen, prefixR)
			e.State, e.Attached = stateSuspect, attached
			return e
		}
		w.send("relay-a", remoteEntry("x", 10, prefixR))
		w.send("relay-a", remoteEntry("y", 20, prefixR))
		require.Equal(t, []string{"y@relay-a"}, entriesOf(w.r, prefixR))
		// The old session goes suspect after the new attach.
		w.send("relay-a", suspectAt(30, 10))
		assert.Equal(t, []string{"y@relay-a"}, entriesOf(w.r, prefixR))
		// The old attachment is in the set. It comes back when the new one ends.
		w.send("relay-a", goneAt("y", 40))
		assert.Equal(t, []string{"x@relay-a"}, entriesOf(w.r, prefixR))
		w.r.mu.RLock()
		assert.Equal(t, stateSuspect, w.r.domains[vpcA].routes[netip.MustParsePrefix(prefixR)].active().state)
		w.r.mu.RUnlock()
		w.check()
	})
}

// TestTwoAttachmentsOnePrefix checks that only the newer of two attachments of
// one session is selected, and the older returns at its detach.
func TestTwoAttachmentsOnePrefix(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newRouteWorld(t, NewRouter(nil, Config{}))
		w.session("local", vpcA, server, thisRevision())
		w.attach("local", "y", prefixA, prefixR)
		w.attach("local", "y2", prefixB, prefixR)
		require.Equal(t, []string{"y2@relay-m"}, entriesOf(w.r, prefixR))
		w.detach("local", "y2")
		assert.Equal(t, []string{"y@relay-m"}, entriesOf(w.r, prefixR))
		assert.True(t, w.sess["local"].sources(netip.MustParsePrefix(prefixR).Addr().Next()))
		w.detach("local", "y")
		assert.Empty(t, w.table(vpcA))
		w.check()
	})
}

// TestStandbySource checks the source check: each announcer of a prefix can
// send from it, also a standby one. A session with no entry cannot.
func TestStandbySource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newRouteWorld(t, NewRouter(nil, Config{}))
		// The agent has a connection to each relay. The one to relay-a is active.
		w.session("local", vpcA, laptop, namedHello("base"))
		w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
		w.attach("local", "y", prefixA)
		w.send("relay-a", remoteEntry("x", 10, prefixA))
		require.Equal(t, []string{"x@relay-a", "y@relay-m"}, entriesOf(w.r, prefixA))

		src := netip.MustParsePrefix(prefixA).Addr().Next()
		assert.True(t, w.sess["local"].sources(src), "the standby announcer can send from the prefix")
		assert.False(t, w.sess["watcher"].sources(src), "a session with no entry can send from the prefix")
		// Packets of the other relay for the prefix go to the announcer of this relay.
		assert.Same(t, w.sess["local"], w.r.localOf(vpcA, src).s)
		assert.Equal(t, "x@relay-a", w.table(vpcA)[prefixA])
		w.check()
	})
}

// TestAnnouncersBetweenRelays checks that two relays select the same announcer
// of one route after their entries cross, and the same standby next.
func TestAnnouncersBetweenRelays(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	a, b := newRouteRelay(t, ca, "relay-a"), newRouteRelay(t, ca, "relay-b")
	sa := a.session(t, "one", "192.0.2.1:1000", thisRevision())
	sb := b.session(t, "two", "192.0.2.2:1000", thisRevision())
	wa := a.session(t, "watcher-a", "192.0.2.3:1000", thisRevision())
	wb := b.session(t, "watcher-b", "192.0.2.4:1000", thisRevision())
	att := func(id, addr string, rank uint32) *Attachment {
		at := attachment(id, addr)
		at.Routes, at.Rank = []netip.Prefix{netip.MustParsePrefix(prefixR)}, rank
		return at
	}
	require.NoError(t, a.r.attach(sa, att("x", "fd00:1::/96", 3)))
	require.NoError(t, b.r.attach(sb, att("y", "fd00:2::/96", 0)))
	require.Equal(t, []string{"x@relay-a"}, entriesOf(a.r, prefixR))
	require.Equal(t, []string{"y@relay-b"}, entriesOf(b.r, prefixR))

	a.n.m.SetMembers([]MeshMember{b.n.member()})
	b.n.m.SetMembers([]MeshMember{a.n.member()})
	b.n.start(t)
	a.n.start(t)
	require.Eventually(t, func() bool {
		return len(entriesOf(a.r, prefixR)) == 2 && len(entriesOf(b.r, prefixR)) == 2
	}, 10*time.Second, 5*time.Millisecond, "each relay has the two announcers")
	order := entriesOf(a.r, prefixR)
	require.Equal(t, order, entriesOf(b.r, prefixR), "the two relays have the same order")

	// The rank of an attachment goes to the other relay.
	b.r.mu.RLock()
	for _, e := range b.r.domains[vpcA].orderOf(netip.MustParsePrefix(prefixR)) {
		if e.origin == "x" {
			assert.EqualValues(t, 3, e.rank)
		}
	}
	b.r.mu.RUnlock()

	// Each agent can send from the prefix on its relay, also the standby one.
	src := netip.MustParsePrefix(prefixR).Addr().Next()
	assert.True(t, sa.sources(src))
	assert.True(t, sb.sources(src))

	// The sessions of other agents get the active announcer of the prefix.
	active, standby := "x", "y"
	stop := func() { _, _, err := a.r.detach(sa, "x"); require.NoError(t, err) }
	if order[0] == "y@relay-b" {
		active, standby = "y", "x"
		stop = func() { _, _, err := b.r.detach(sb, "y"); require.NoError(t, err) }
	}
	a.has(t, wa, "x fd00:1::/96", "y fd00:2::/96", active+" "+prefixR)
	b.has(t, wb, "x fd00:1::/96", "y fd00:2::/96", active+" "+prefixR)

	// The active announcer detaches. The standby one gets the prefix.
	stop()
	left := map[string]string{"x": "y fd00:2::/96", "y": "x fd00:1::/96"}[active]
	a.has(t, wa, left, standby+" "+prefixR)
	b.has(t, wb, left, standby+" "+prefixR)
	require.Len(t, entriesOf(a.r, prefixR), 1)
	assert.Equal(t, entriesOf(a.r, prefixR), entriesOf(b.r, prefixR))
}

// setState gives the entries of s the state, as the liveness check and the
// drain of a relay do.
func setState(r *Router, s *Session, state dp.AnnouncerState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setState(s, state, "test", time.Now())
}

// heldFor returns e with a hold time that ends d after now.
func heldFor(e *dp.Presence, d time.Duration) *dp.Presence {
	e.ActiveFrom = timestamppb.New(time.Now().Add(d))
	return e
}

// suspect returns e in the suspect state.
func suspect(e *dp.Presence) *dp.Presence {
	e.State = stateSuspect
	return e
}

// TestSetState checks that a state change keeps the rows to a sole announcer,
// and sends a RouteDelta only when the order changes.
func TestSetState(t *testing.T) {
	const rowDst = "fd00:a::1"
	cases := []struct {
		name string
		// rank is the rank of the attachment x of the agent on relay-a. Zero
		// is no such attachment. The attachment y of this relay has rank 2.
		rank  uint32
		steps func(w *routeWorld)
		order []string // Announcers of prefixR at the end, in the order of selection.
		delta []string // Changes that the watcher gets in steps.
	}{
		{
			name:  "sole announcer goes suspect: it stays active",
			steps: func(w *routeWorld) { setState(w.r, w.sess["local"], stateSuspect) },
			order: []string{"y@relay-m"},
		},
		{
			name:  "sole announcer goes draining: it stays active",
			steps: func(w *routeWorld) { setState(w.r, w.sess["local"], stateDraining) },
			order: []string{"y@relay-m"},
		},
		{
			name:  "active announcer goes suspect: the standby one is active",
			rank:  3,
			steps: func(w *routeWorld) { setState(w.r, w.sess["local"], stateSuspect) },
			order: []string{"x@relay-a", "y@relay-m"},
			delta: []string{"-y " + prefixR, "+x " + prefixR + " standby=y"},
		},
		{
			name:  "active announcer goes draining: the standby one is active",
			rank:  3,
			steps: func(w *routeWorld) { setState(w.r, w.sess["local"], stateDraining) },
			order: []string{"x@relay-a", "y@relay-m"},
			delta: []string{"-y " + prefixR, "+x " + prefixR + " standby=y"},
		},
		{
			name:  "standby announcer goes suspect: the order stays",
			rank:  1,
			steps: func(w *routeWorld) { setState(w.r, w.sess["local"], stateSuspect) },
			order: []string{"x@relay-a", "y@relay-m"},
		},
		{
			name: "suspect announcer is normal again: it is active only after its hold time",
			rank: 3,
			steps: func(w *routeWorld) {
				setState(w.r, w.sess["local"], stateSuspect)
				w.drain()
				setState(w.r, w.sess["local"], stateNormal)
				time.Sleep(holdTime - time.Nanosecond)
				synctest.Wait()
				require.Equal(w.t, []string{"x@relay-a", "y@relay-m"}, entriesOf(w.r, prefixR))
				require.Empty(w.t, w.changes("watcher"), "changes in the hold time")
				time.Sleep(time.Nanosecond)
				synctest.Wait()
			},
			order: []string{"y@relay-m", "x@relay-a"},
			delta: []string{"-x " + prefixR, "+y " + prefixR + " standby=x"},
		},
		{
			name: "session that closed gets no state",
			steps: func(w *routeWorld) {
				w.r.removeSession(w.sess["local"])
				w.drain()
				setState(w.r, w.sess["local"], stateSuspect)
			},
			order: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				watcher := w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				local := w.session("local", vpcA, laptop, namedHello("base"))
				y := attachment("y", prefixA)
				y.Routes, y.Rank = []netip.Prefix{netip.MustParsePrefix(prefixR)}, 2
				require.NoError(t, w.r.attach(local, y))
				if tc.rank != 0 {
					w.send("relay-a", ranked(remoteEntry("x", 10, prefixR), tc.rank))
				}
				endHold()
				require.NoError(t, w.r.registerSPI(watcher, register(vpcA, rowDst, time.Hour, 5), time.Now()))
				w.drain()

				tc.steps(w)
				assert.Equal(t, tc.order, entriesOf(w.r, prefixR))
				assert.Equal(t, tc.delta, w.changes("watcher"))
				w.r.mu.RLock()
				defer w.r.mu.RUnlock()
				if local.closed {
					assert.Empty(t, watcher.rows, "rows to a session that closed")
					return
				}
				// The address has one announcer, so a remove of its entry ends the row.
				require.Contains(t, watcher.rows, uint32(5), "row to the address of the session")
				assert.Same(t, local, watcher.rows[5].receiver)
			})
		})
	}
}

// TestSetStatePresence checks the entries that a state change sends: a higher
// generation, and a new hold time only at a return to normal.
func TestSetStatePresence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newRouteWorld(t, NewRouter(nil, Config{}))
		local := w.session("local", vpcA, laptop, namedHello("base"))
		var sent []*dp.Presence
		w.r.mu.Lock()
		w.r.presence = func(e *dp.Presence) { sent = append(sent, e) }
		w.r.mu.Unlock()
		w.attach("local", "y", prefixA)
		w.attach("local", "y2", prefixB)
		require.Len(t, sent, 2)
		attached := map[string]*dp.Presence{"y": sent[0], "y2": sent[1]}
		for id, e := range attached {
			assert.Equal(t, e.GetGeneration(), e.GetAttached(), "generation of the attach of %s", id)
			assert.Equal(t, time.Now().Add(holdTime), e.GetActiveFrom().AsTime().Local(), "hold time of %s", id)
		}

		steps := []struct {
			state dp.AnnouncerState
			hold  bool // The entries have a new hold time.
		}{
			{state: stateSuspect},
			{state: stateDraining},
			{state: stateNormal, hold: true},
		}
		last := attached
		for _, st := range steps {
			time.Sleep(time.Minute)
			sent = nil
			setState(w.r, local, st.state)
			require.Len(t, sent, 2, "entries for the state %s", st.state)
			now := map[string]*dp.Presence{}
			for _, e := range sent {
				id := e.GetAttachmentId()
				now[id] = e
				assert.Equal(t, st.state, e.GetState(), id)
				assert.Greater(t, e.GetGeneration(), last[id].GetGeneration(), "generation of %s", id)
				assert.Equal(t, attached[id].GetAttached(), e.GetAttached(), "generation of the attach of %s", id)
				assert.Equal(t, attached[id].GetPrefixes(), e.GetPrefixes(), id)
				want := last[id].GetActiveFrom().AsTime()
				if st.hold {
					want = time.Now().Add(holdTime)
				}
				assert.True(t, want.Equal(e.GetActiveFrom().AsTime()), "hold time of %s", id)
			}
			require.Len(t, now, 2)
			last = now
		}

		// The same state again sends nothing.
		sent = nil
		setState(w.r, local, stateNormal)
		assert.Empty(t, sent)
		// A new attachment of a session has the state of the session.
		setState(w.r, local, stateSuspect)
		sent = nil
		w.attach("local", "y3", prefixR)
		require.Len(t, sent, 1)
		assert.Equal(t, stateSuspect, sent[0].GetState())
	})
}

// TestHoldTime checks the hold time of an announcer that comes or returns. The
// agent has x on relay-a, with the lower rank, and y on relay-b.
func TestHoldTime(t *testing.T) {
	x := func() *dp.Presence { return remoteEntry("x", 10, prefixR) }
	y := func() *dp.Presence { return ranked(remoteEntry("y", 10, prefixR), 1) }
	cases := []struct {
		name    string
		entries func() []*dp.Presence
		// before is the order of the announcers until the first hold time ends,
		// and after is the order when it ended.
		before, after []string
		delta         []string // Changes that the watcher gets at the end of the hold time.
		// last is the order when the second hold time ended, after two times
		// holdTime, and lastDelta has the changes at that end. Nil is after.
		last, lastDelta []string
	}{
		{
			name:    "returning announcer waits for the end of its hold time",
			entries: func() []*dp.Presence { return []*dp.Presence{heldFor(x(), holdTime), y()} },
			before:  []string{"y@relay-b", "x@relay-a"},
			after:   []string{"x@relay-a", "y@relay-b"},
			delta:   []string{"-y " + prefixR, "+x " + prefixR + " standby=y"},
		},
		{
			name:    "no wait when the active announcer is draining",
			entries: func() []*dp.Presence { return []*dp.Presence{heldFor(x(), holdTime), draining(y())} },
			before:  []string{"x@relay-a", "y@relay-b"},
			after:   []string{"x@relay-a", "y@relay-b"},
		},
		{
			name:    "no wait when the active announcer is suspect",
			entries: func() []*dp.Presence { return []*dp.Presence{heldFor(x(), holdTime), suspect(y())} },
			before:  []string{"x@relay-a", "y@relay-b"},
			after:   []string{"x@relay-a", "y@relay-b"},
		},
		{
			name:    "no wait when the active announcer is gone",
			entries: func() []*dp.Presence { return []*dp.Presence{heldFor(x(), holdTime), y(), goneAt("y", 11)} },
			before:  []string{"x@relay-a"},
			after:   []string{"x@relay-a"},
		},
		{
			name: "each announcer is in its hold time: one is active at once",
			entries: func() []*dp.Presence {
				return []*dp.Presence{heldFor(x(), holdTime), heldFor(y(), holdTime)}
			},
			before: []string{"x@relay-a", "y@relay-b"},
			after:  []string{"x@relay-a", "y@relay-b"},
		},
		{
			// The usual order comes back only when the second hold time ends.
			name: "each announcer is in its hold time: the one that ends first is active and stays",
			entries: func() []*dp.Presence {
				return []*dp.Presence{heldFor(x(), 2*holdTime), heldFor(y(), holdTime)}
			},
			before:    []string{"y@relay-b", "x@relay-a"},
			after:     []string{"y@relay-b", "x@relay-a"},
			last:      []string{"x@relay-a", "y@relay-b"},
			lastDelta: []string{"-y " + prefixR, "+x " + prefixR + " standby=y"},
		},
		{
			name: "each announcer is in its hold time: no change when the usual order is the same",
			entries: func() []*dp.Presence {
				return []*dp.Presence{heldFor(x(), holdTime), heldFor(y(), 2*holdTime)}
			},
			before: []string{"x@relay-a", "y@relay-b"},
			after:  []string{"x@relay-a", "y@relay-b"},
		},
		{
			name:    "hold time that ended before the entry came",
			entries: func() []*dp.Presence { return []*dp.Presence{heldFor(x(), -time.Second), y()} },
			before:  []string{"x@relay-a", "y@relay-b"},
			after:   []string{"x@relay-a", "y@relay-b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Two relays get the same entries, in two orders.
				w, other := newRouteWorld(t, NewRouter(nil, Config{})), newRouteWorld(t, NewRouter(nil, Config{}))
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				other.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				member := map[string]string{"x": "relay-a", "y": "relay-b"}
				for _, e := range tc.entries() {
					w.send(member[e.GetAttachmentId()], e)
				}
				// The end of an attachment comes after its entry on each relay.
				opposite := tc.entries()
				slices.Reverse(opposite)
				slices.SortStableFunc(opposite, func(a, b *dp.Presence) int {
					return cmp.Compare(btoi(a.GetGone()), btoi(b.GetGone()))
				})
				for _, e := range opposite {
					other.send(member[e.GetAttachmentId()], e)
				}
				w.drain()
				assert.Equal(t, tc.before, entriesOf(w.r, prefixR), "at the start")
				assert.Equal(t, tc.before, entriesOf(other.r, prefixR), "at the start, on the other relay")

				time.Sleep(holdTime - time.Nanosecond)
				synctest.Wait()
				assert.Equal(t, tc.before, entriesOf(w.r, prefixR), "before the end of the hold time")
				assert.Equal(t, tc.before, entriesOf(other.r, prefixR), "before the end of the hold time, on the other relay")
				assert.Empty(t, w.changes("watcher"), "changes in the hold time")

				time.Sleep(time.Nanosecond)
				synctest.Wait()
				assert.Equal(t, tc.after, entriesOf(w.r, prefixR), "after the hold time")
				assert.Equal(t, tc.after, entriesOf(other.r, prefixR), "after the hold time, on the other relay")
				assert.Equal(t, tc.delta, w.changes("watcher"))

				if tc.last == nil {
					tc.last = tc.after
				}
				time.Sleep(holdTime)
				synctest.Wait()
				assert.Equal(t, tc.last, entriesOf(w.r, prefixR), "after the second hold time")
				assert.Equal(t, tc.last, entriesOf(other.r, prefixR), "after the second hold time, on the other relay")
				assert.Equal(t, tc.lastDelta, w.changes("watcher"))
				w.check()
				other.check()
			})
		})
	}
}

// TestAttachHold checks that a new attachment of this relay replaces a live
// active announcer of its prefix only 30 s after its attach.
func TestAttachHold(t *testing.T) {
	// The hold time of the design, and not the constant of the code.
	const hold = 30 * time.Second
	// x is the entry of relay-a. With rank 3, the new attachment y (rank 2) of
	// the same agent comes first in the usual order.
	x := func(rank uint32) *dp.Presence { return ranked(remoteEntry("x", 10, prefixR), rank) }
	xFirst, yFirst := []string{"x@relay-a", "y@relay-m"}, []string{"y@relay-m", "x@relay-a"}
	toY := []string{"-x " + prefixR, "+y " + prefixR + " standby=x"}
	cases := []struct {
		name string
		// x returns the entry of x, which is active before the attach. It runs
		// on the fake clock.
		x func() *dp.Presence
		// before is the order until the hold time of y ends, and after is the
		// order from that end.
		before, after []string
		delta         []string // Changes that the watcher gets at that end.
	}{
		{
			name:   "active announcer is normal: the new one waits for its hold time",
			x:      func() *dp.Presence { return x(3) },
			before: xFirst, after: yFirst, delta: toY,
		},
		{
			// Each entry is held: the one whose hold ends first is active.
			name:   "active announcer attached 10 s before: it stays until the hold time of the new one ends",
			x:      func() *dp.Presence { return heldFor(x(3), hold-10*time.Second) },
			before: xFirst, after: yFirst, delta: toY,
		},
		{
			name:   "active announcer is suspect: the new one is active at once",
			x:      func() *dp.Presence { return suspect(x(3)) },
			before: yFirst, after: yFirst,
		},
		{
			name:   "active announcer is draining: the new one is active at once",
			x:      func() *dp.Presence { return draining(x(3)) },
			before: yFirst, after: yFirst,
		},
		{
			name:   "new one is after the active one in the usual order: no change",
			x:      func() *dp.Presence { return x(1) },
			before: xFirst, after: xFirst,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				local := w.session("local", vpcA, laptop, namedHello("base"))
				w.send("relay-a", tc.x())
				require.Equal(t, []string{"x@relay-a"}, entriesOf(w.r, prefixR))
				w.drain()

				y := attachment("y", prefixA)
				y.Routes, y.Rank = []netip.Prefix{netip.MustParsePrefix(prefixR)}, 2
				require.NoError(t, w.r.attach(local, y))
				assert.Equal(t, tc.before, entriesOf(w.r, prefixR), "at the attach")
				w.drain()

				time.Sleep(hold - time.Nanosecond)
				synctest.Wait()
				assert.Equal(t, tc.before, entriesOf(w.r, prefixR), "before the end of the hold time")
				assert.Empty(t, w.changes("watcher"), "changes in the hold time")

				time.Sleep(time.Nanosecond)
				synctest.Wait()
				assert.Equal(t, tc.after, entriesOf(w.r, prefixR), "at the end of the hold time")
				assert.Equal(t, tc.delta, w.changes("watcher"))
				w.check()
			})
		})
	}
}

// TestHoldTimer checks that the router has one timer for the hold times of all
// prefixes, and that the selection runs again for each prefix at its time.
func TestHoldTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newRouteWorld(t, NewRouter(nil, Config{}))
		w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
		const prefixes = 8
		first := func(n int) string { return entriesOf(w.r, fmt.Sprintf("10.%d.0.0/16", n))[0] }
		for n := range prefixes {
			p := fmt.Sprintf("10.%d.0.0/16", n)
			w.send("relay-b", ranked(remoteEntry(fmt.Sprintf("y%d", n), 10, p), 1))
			// The hold time of the prefix n ends n+1 seconds from now.
			w.send("relay-a", heldFor(remoteEntry(fmt.Sprintf("x%d", n), 10, p), time.Duration(n+1)*time.Second))
			require.Equal(t, fmt.Sprintf("y%d@relay-b", n), first(n))
		}
		w.r.mu.RLock()
		timer := w.r.holdTimer
		assert.Len(t, w.r.holds, prefixes, "pending ends")
		w.r.mu.RUnlock()
		require.NotNil(t, timer)
		for n := range prefixes {
			time.Sleep(time.Second)
			synctest.Wait()
			assert.Equal(t, fmt.Sprintf("x%d@relay-a", n), first(n), "prefix %d at its time", n)
			if n+1 < prefixes {
				assert.Equal(t, fmt.Sprintf("y%d@relay-b", n+1), first(n+1), "prefix %d before its time", n+1)
			}
		}
		w.r.mu.RLock()
		assert.Same(t, timer, w.r.holdTimer)
		assert.Empty(t, w.r.holds)
		w.r.mu.RUnlock()
	})
}

// TestAnnouncerHash checks the hash of an entry against entryHash, also for an
// agent ID that is longer than the buffer of the hash.
func TestAnnouncerHash(t *testing.T) {
	cases := []struct {
		name     string
		agent    string
		instance uint64
		prefix   string
	}{
		{name: "IPv6 prefix", agent: "a", prefix: prefixA},
		{name: "IPv4 prefix", agent: "a", prefix: prefixR},
		{name: "IPv4 prefix in the IPv6 form", agent: "a", prefix: "::ffff:10.9.0.0/112"},
		{name: "instance", agent: "a", instance: 1<<63 + 7, prefix: prefixA},
		{name: "long agent ID", agent: strings.Repeat("a", 600), instance: 3, prefix: prefixA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tc.prefix)
			e := entrySpec{agent: tc.agent, instance: tc.instance}.entry(p)
			assert.Equal(t, entryHash(tc.agent, tc.instance, p), e.hash[:])
		})
	}
}

// TestAttachmentRecord checks that the entries of each prefix of an attachment
// read one record, so one write of a state reaches each prefix.
func TestAttachmentRecord(t *testing.T) {
	cases := []struct {
		name string
		// setup makes an attachment with prefixA and prefixR, and returns its record.
		setup  func(w *routeWorld) *candidate
		change func(w *routeWorld)
	}{
		{
			name: "attachment of this relay",
			setup: func(w *routeWorld) *candidate {
				a := attachment("y", prefixA)
				a.Routes = []netip.Prefix{netip.MustParsePrefix(prefixR)}
				require.NoError(w.t, w.r.attach(w.session("local", vpcA, laptop, namedHello("base")), a))
				return &a.cand
			},
			change: func(w *routeWorld) { setState(w.r, w.sess["local"], stateSuspect) },
		},
		{
			name: "attachment of another relay",
			setup: func(w *routeWorld) *candidate {
				w.send("relay-a", remoteEntry("x", 10, prefixA, prefixR))
				w.m.pres.mu.Lock()
				defer w.m.pres.mu.Unlock()
				return &w.m.pres.in["relay-a"].entries["x"].cand
			},
			change: func(w *routeWorld) {
				e := suspect(remoteEntry("x", 30, prefixA, prefixR))
				e.Attached = 10
				w.send("relay-a", e)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				record := tc.setup(w)
				tc.change(w)
				w.r.mu.RLock()
				defer w.r.mu.RUnlock()
				assert.Equal(t, stateSuspect, record.state)
				for _, p := range []string{prefixA, prefixR} {
					set := w.r.domains[vpcA].routes[netip.MustParsePrefix(p)]
					require.Len(t, set.entries, 1, "entries of %s", p)
					assert.Same(t, record, set.entries[0].candidate, "record of the entry of %s", p)
				}
			})
		})
	}
}

// TestStateChangeWork checks that each entry gets a new state, but the rows of
// mesh members get checks again only when the order is new.
func TestStateChangeWork(t *testing.T) {
	cases := []struct {
		name  string
		rank  uint32 // Rank of x. Zero is no such attachment.
		state dp.AnnouncerState
		epoch bool // The router starts a new epoch.
	}{
		{name: "sole announcer goes suspect: no new order", state: stateSuspect},
		{name: "sole announcer goes draining: no new order", state: stateDraining},
		{name: "standby announcer goes suspect: no new order", rank: 1, state: stateSuspect},
		{name: "active announcer goes suspect: new order", rank: 3, state: stateSuspect, epoch: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newRouteWorld(t, NewRouter(nil, Config{}))
				w.session("watcher", vpcA, agentID(vpcA, "watcher"), thisRevision())
				local := w.session("local", vpcA, laptop, namedHello("base"))
				y := attachment("y", prefixA)
				y.Routes, y.Rank = []netip.Prefix{netip.MustParsePrefix(prefixR)}, 2
				require.NoError(t, w.r.attach(local, y))
				if tc.rank != 0 {
					w.send("relay-a", ranked(remoteEntry("x", 10, prefixR), tc.rank))
				}
				endHold()
				w.drain()
				before := w.r.epoch.Load()

				setState(w.r, local, tc.state)
				assert.Equal(t, tc.epoch, w.r.epoch.Load() != before, "new epoch")
				assert.Equal(t, tc.epoch, len(w.changes("watcher")) > 0, "changes for the watcher")
				for _, p := range []string{prefixA, prefixR} {
					state, ok := entryState(w.r, p, "y")
					require.True(t, ok, "entry of y for %s", p)
					assert.Equal(t, tc.state, state, "state of y for %s", p)
				}
			})
		})
	}
}
