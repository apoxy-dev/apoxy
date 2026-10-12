// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	stateNormal   = dp.AnnouncerState_ANNOUNCER_STATE_NORMAL
	stateDraining = dp.AnnouncerState_ANNOUNCER_STATE_DRAINING
	stateSuspect  = dp.AnnouncerState_ANNOUNCER_STATE_SUSPECT
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
}

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
	return newAnnouncer(target{s: s, origin: spec.id}, spec.relay, p, spec.gen, spec.rank, spec.state)
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			permutations(len(tc.entries), func(order []int) {
				entries := make([]*announcer, len(order))
				for i, n := range order {
					entries[i] = tc.entries[n].entry(p)
				}
				assert.Equal(t, tc.want, orderNames(selectOrder(entries)), "entries in the order %v", order)
			})
		})
	}
}

// TestSelectOrderByHash checks the order of two agents: the hash of the agent
// and the prefix decides, and the connections of one agent stay together.
// Each prefix has its own order, so one agent does not get them all.
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
			require.Equal(t, want, orderNames(selectOrder(entries)), "prefix %s, entries in the order %v", p, order)
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
		want  announcer
	}{
		{
			name:  "member from before the revision: instance 0, rank 0, normal state",
			entry: remoteEntry("x", 10, prefixR),
			want:  announcer{agent: agentKey{id: laptop, name: "base"}, attached: 10, state: stateNormal},
		},
		{
			name: "instance, rank and state",
			entry: func() *dp.Presence {
				e := ranked(draining(remoteEntry("x", 10, prefixR)), 2)
				e.Instance = 77
				return e
			}(),
			want: announcer{agent: agentKey{id: laptop, name: "base", instance: 77}, attached: 10, rank: 2, state: stateDraining},
		},
		{
			name: "entry with a new state: the generation at the attach stays",
			entry: func() *dp.Presence {
				e := draining(remoteEntry("x", 30, prefixR))
				e.Attached = 10
				return e
			}(),
			want: announcer{agent: agentKey{id: laptop, name: "base"}, attached: 10, state: stateDraining},
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

// TestReconnectThenStateChange checks a reconnect to one relay when the entry
// of the old attachment gets a new state after it: the higher generation of
// that entry does not bring the old attachment back in the selection.
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

// TestTwoAttachmentsOnePrefix checks two attachments of one session with the
// same advertised route. Only the newer one is in the selection. The older one
// stays in the set, and it comes back when the newer one detaches.
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

// TestAnnouncersBetweenRelays runs two relays. An agent of each relay attaches
// with the same advertised route before the mesh sessions open. After the
// entries cross, the two relays select the same announcer. At the detach of
// the active announcer, the standby one gets the prefix on both relays.
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
