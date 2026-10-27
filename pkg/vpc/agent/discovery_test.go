// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// quietWait is how long a check waits for a dial that must not come. It is
// longer than the first backoff of a relay.
const quietWait = 1500 * time.Millisecond

// byName returns the address of r with the host name localhost, for a relay
// with the ID localhost that the agent dials with no ID.
func (r *testRelay) byName() string {
	_, port, _ := net.SplitHostPort(r.addr)
	return net.JoinHostPort("localhost", port)
}

// dials returns the Session calls of ta that the relays got.
func (ta *testAgent) dials(relays ...*testRelay) int {
	n := 0
	for _, r := range relays {
		n += len(r.sessionConns(ta.tr.Conn.LocalAddr()))
	}
	return n
}

// attachments returns the attachments named name on the relays.
func attachments(name string, relays ...*testRelay) int {
	n := 0
	for _, r := range relays {
		for _, st := range r.r.AttachmentStats() {
			if st.Name == name {
				n++
			}
		}
	}
	return n
}

// TestOwnRelayRoutes checks that a route that names the relay of the session
// makes no dial, with the relay configured by its ID or by its address only.
func TestOwnRelayRoutes(t *testing.T) {
	cases := []struct {
		name      string
		byAddress bool
	}{
		{name: "relay configured with its ID"},
		{name: "relay configured with its address only", byAddress: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "localhost")
			ref := r.ref()
			if tc.byAddress {
				ref = identity.Relay{Addresses: []string{r.byName()}}
			}
			a := w.agent(t, "a", r, agentOptions{relays: []identity.Relay{ref}})
			a.attached(t)
			b := w.agent(t, "b", r, agentOptions{})
			eb := b.attached(t)
			a.hasRoutes(t, eb.prefixes[0])
			require.Eventually(t, func() bool { return a.dials(r) == 1 }, 5*time.Second, 10*time.Millisecond, "dials of the relay")
			require.Never(t, func() bool { return a.dials(r) != 1 }, quietWait, 10*time.Millisecond, "dial for a route that names the relay of the session")
			assert.Len(t, a.a.Status().Connections, 1)
		})
	}
}

// TestPrimaryRedial checks that the agent dials the relay of its last primary
// once when the connection ends, although the routes and the config both name it.
func TestPrimaryRedial(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{})
	a.attached(t)
	b := w.agent(t, "b", r, agentOptions{})
	eb := b.attached(t)
	a.hasRoutes(t, eb.prefixes[0])
	a.reconnect()
	a.attached(t)
	require.Eventually(t, func() bool { return a.dials(r) == 2 }, 5*time.Second, 10*time.Millisecond, "dials of the relay")
	require.Never(t, func() bool { return a.dials(r) != 2 }, quietWait, 10*time.Millisecond, "dials of the relay")
	assert.Len(t, a.a.Status().Connections, 1)
}

// TestRelayKey checks that the agent keys a connection by the relay ID of its
// Welcome: it keeps one connection to a relay ID, whatever addresses it dialed.
func TestRelayKey(t *testing.T) {
	cases := []struct {
		name string
		// two gives the relay ID localhost to two relays, which the agent dials
		// as two addresses with no ID. Else one relay has it.
		two      bool
		sessions int  // Config.Sessions.
		hold     bool // The relays hold the Attach calls until both connections to localhost are open.
		close    bool // The relay closes the attached connection to localhost.
		dials    int  // Connections to localhost at the end.
	}{
		{name: "relay configured with its address only", sessions: 2, dials: 1},
		{name: "two addresses of one relay ID", two: true, sessions: 3, dials: 2},
		{name: "two addresses of one relay ID, the first attach held", two: true, sessions: 3, hold: true, dials: 2},
		{name: "two addresses of one relay ID, the relay closes the connection", two: true, sessions: 3, close: true, dials: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			rs := []*testRelay{w.relay(t, "localhost")}
			if tc.two {
				rs = append(rs, w.relay(t, "localhost"))
			}
			rb := w.relay(t, "relay-b")
			var addrs []string
			for _, r := range rs {
				addrs = append(addrs, r.byName())
			}
			release := func() {}
			if tc.hold {
				release = w.addrs.hold("a")
			}
			a := w.agent(t, "a", rb, agentOptions{sessions: tc.sessions, relays: []identity.Relay{{Addresses: addrs}, rb.ref()}})
			if tc.hold {
				require.Eventually(t, func() bool { return a.dials(rs...) == 2 }, 10*time.Second, 10*time.Millisecond, "dials of localhost")
				require.Never(t, func() bool { now, _ := w.addrs.held(); return now > 2 }, quietWait/3, 10*time.Millisecond, "held attaches")
				release()
			}
			a.attached(t)
			a.attached(t)
			if tc.close {
				for _, r := range rs {
					for _, qc := range r.agentConns(a.tr.Conn.LocalAddr(), true) {
						require.NoError(t, qc.CloseWithError(0, "relay closed the session"))
					}
				}
				a.attached(t)
			}
			require.Eventually(t, func() bool { return a.dials(rs...) == tc.dials }, 5*time.Second, 10*time.Millisecond, "dials of localhost")
			require.Never(t, func() bool { return a.dials(rs...) != tc.dials }, quietWait, 10*time.Millisecond, "dials of localhost")
			assert.Equal(t, 1, attachments("a", rs...), "attachments on localhost")
			assert.Equal(t, 1, a.dials(rb), "dials of relay-b")
			if tc.hold {
				_, most := w.addrs.held()
				assert.Equal(t, 2, most, "a second connection to localhost ends before its attach")
			}
			var relays []string
			for _, c := range a.a.Status().Connections {
				relays = append(relays, c.Relay)
			}
			assert.Len(t, relays, 2)
			assert.Contains(t, relays, rb.addr)
		})
	}
}

// TestPrimaryRoutes checks that OnRoutes has the routes of the primary
// relay, and the routes of the next one alone after the primary ends.
func TestPrimaryRoutes(t *testing.T) {
	w := newWorld(t)
	ra, rb := w.relay(t, "relay-a"), w.relay(t, "relay-b")
	shared := netip.MustParsePrefix("2001:db8:2::/64")
	routes := map[*testRelay][]netip.Prefix{
		ra: {netip.MustParsePrefix("2001:db8:1::/64"), shared},
		rb: {netip.MustParsePrefix("2001:db8:3::/64"), shared},
	}
	for i, r := range []*testRelay{ra, rb} {
		o := w.agent(t, fmt.Sprintf("other-%d", i), r, agentOptions{routes: routes[r]})
		routes[r] = append(routes[r], o.attached(t).prefixes...)
	}
	a, rcs := w.agentOn(t, "a", agentOptions{}, 2, ra, rb)
	primary, next := w.relayAt(rcs[0].addr), w.relayAt(rcs[1].addr)
	exactly := func(want []netip.Prefix) {
		t.Helper()
		require.Eventually(t, func() bool {
			got := a.routeSet()
			return len(got) == len(want) && !slices.ContainsFunc(want, func(p netip.Prefix) bool { return !slices.Contains(got, p) })
		}, 5*time.Second, 10*time.Millisecond, "routes %v, want %v", a.routeSet(), want)
	}
	exactly(routes[primary])
	require.NoError(t, rcs[0].qc.CloseWithError(0, "relay closed the session"))
	exactly(routes[next])
	for _, p := range routes[primary] {
		if slices.Contains(routes[next], p) {
			assert.Equal(t, []string{"+" + p.String()}, a.routeEvents(p), "a route of both relays stays")
		} else {
			assert.Equal(t, []string{"+" + p.String(), "-" + p.String()}, a.routeEvents(p), "a route of the old primary alone goes")
		}
	}
}

// TestRelayBackoff checks that each relay has its own backoff: the failures
// of relay-b do not delay the redial of relay-a.
func TestRelayBackoff(t *testing.T) {
	w := newWorld(t)
	// The relays write each change at once. With the write interval, relay-b can refuse two dials
	// before the first attach on relay-a, and the agent then stops.
	w.relayCfg.TableWriteInterval = new(time.Duration(0))
	w.refuse = map[string]string{"relay-b": "agent too old"}
	ra, rb := w.relay(t, "relay-a"), w.relay(t, "relay-b")
	a := w.agent(t, "a", ra, agentOptions{sessions: 2, relays: []identity.Relay{ra.ref(), rb.ref()}, runErr: make(chan error, 1)})
	a.attached(t)
	// relay-b refuses three dials, so its backoff is above a second.
	require.Eventually(t, func() bool { return rb.refused.Load() >= 3 }, 15*time.Second, 10*time.Millisecond)
	start := time.Now()
	a.reconnect()
	a.attached(t)
	assert.Less(t, time.Since(start), minBackoff, "attach of relay-a after its connection ended")
	assert.Equal(t, 2, a.dials(ra))
}

// testNetwork is the /72 of the VPC network testVNI. A /88 in it is a slot.
var testNetwork = netip.MustParsePrefix("fd61:706f:7879:a0b:c00::/72")

// slotAddr returns the address /96 with the index 1 in the slot s of
// testNetwork, and the slot /88.
func slotAddr(s int) (addr, slot netip.Prefix) {
	b := testNetwork.Addr().As16()
	b[9], b[10], b[11] = byte(s>>8), byte(s), 1
	a := netip.AddrFrom16(b)
	return netip.PrefixFrom(a, 96), netip.PrefixFrom(a, 88).Masked()
}

// TestWantedRelays checks that a route that names another relay of the mesh
// makes the agent dial that relay and attach there with the next rank, apart
// from Config.Sessions, and that data passes between each two agents on the
// relay of their first session.
func TestWantedRelays(t *testing.T) {
	type meshAgent struct {
		relay int // 1 for relay-1.
		slot  int // Slot of the first address in testNetwork. Zero gives an address outside it.
	}
	cases := []struct {
		name   string
		relays int
		mode   TransportMode
		agents []meshAgent // a, b, c, d.
		// dead gives relay-2 an agent address that does not answer.
		dead bool
		// want has the relays of the connections of each agent, by name.
		want map[string][]int
	}{
		{
			name: "route of an agent on the relay of the session", relays: 2,
			agents: []meshAgent{{relay: 1}, {relay: 1}},
			want:   map[string][]int{"a": {1}, "b": {1}},
		},
		{
			name: "route of an agent on another relay", relays: 2,
			agents: []meshAgent{{relay: 1}, {relay: 2}},
			want:   map[string][]int{"a": {1, 2}, "b": {2, 1}},
		},
		{
			name: "address of the other relay does not answer", relays: 2, dead: true,
			agents: []meshAgent{{relay: 1}, {relay: 2}},
			want:   map[string][]int{"a": {1}, "b": {2, 1}},
		},
		{
			name: "twelve sessions in QUIC mode", relays: 4, mode: TransportQUIC,
			agents: []meshAgent{{relay: 1}, {relay: 2}, {relay: 3}, {relay: 4}},
			want:   map[string][]int{"a": {1, 2, 3, 4}, "b": {2, 1, 3, 4}, "c": {3, 1, 2, 4}, "d": {4, 1, 2, 3}},
		},
		{
			name: "slots 255 to 257", relays: 3,
			agents: []meshAgent{{relay: 1, slot: 1}, {relay: 2, slot: 255}, {relay: 3, slot: 256}, {relay: 2, slot: 257}},
			want:   map[string][]int{"a": {1, 2, 3}, "b": {2, 1, 3}, "c": {3, 1, 2}, "d": {2, 1, 3}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.mesh = true
			if tc.dead {
				w.advertise = map[string][]string{"relay-2": {deadRelay(t)}}
			}
			var relays []*testRelay
			for i := range tc.relays {
				relays = append(relays, w.relay(t, fmt.Sprintf("relay-%d", i+1)))
			}
			joinMesh(t, relays...)
			type placed struct {
				name string
				ta   *testAgent
				ev   attachEvent
				r    *testRelay // The relay of its config.
			}
			var agents []placed
			var slots []netip.Prefix
			for i, m := range tc.agents {
				name := string(rune('a' + i))
				if m.slot != 0 {
					addr, slot := slotAddr(m.slot)
					w.addrs.fix(name, addr)
					slots = append(slots, slot)
				}
				r := relays[m.relay-1]
				ta := w.agent(t, name, r, agentOptions{mode: tc.mode})
				agents = append(agents, placed{name: name, ta: ta, ev: ta.attached(t), r: r})
			}
			// connsOf returns the relay addresses of the connections of ta.
			connsOf := func(ta *testAgent) []string {
				var out []string
				for _, c := range ta.a.Status().Connections {
					out = append(out, c.Relay)
				}
				slices.Sort(out)
				return out
			}
			for _, p := range agents {
				var want []string
				for _, i := range tc.want[p.name] {
					want = append(want, relays[i-1].addr)
				}
				slices.Sort(want)
				require.Eventually(t, func() bool { return slices.Equal(connsOf(p.ta), want) }, 10*time.Second, 10*time.Millisecond,
					"connections of %s: %v, want %v", p.name, connsOf(p.ta), want)
				echo(t, p.ta.stack, p.ev.addr, 9000)
			}
			if len(slots) > 0 {
				agents[0].ta.hasRoutes(t, slots[1:]...)
			}
			covers := func(ta *testAgent, a netip.Addr) bool {
				return slices.ContainsFunc(ta.routeSet(), func(p netip.Prefix) bool { return p.Contains(a) })
			}
			for _, from := range agents {
				for _, to := range agents {
					if from.name != to.name {
						require.Eventually(t, func() bool { return covers(from.ta, to.ev.addr) }, 5*time.Second, 10*time.Millisecond,
							"route of %s to %s", from.name, to.name)
						ping(t, from.ta.stack, from.ev.addr, to.ev.addr, 9000, from.name+" to "+to.name)
					}
				}
			}
			require.Never(t, func() bool {
				return slices.ContainsFunc(agents, func(p placed) bool { return len(p.ta.a.Status().Connections) != len(tc.want[p.name]) })
			}, quietWait, 20*time.Millisecond, "an agent opened or closed a connection")
			for _, p := range agents {
				cs := p.ta.a.Status().Connections
				var ranks []uint32
				for _, c := range cs {
					ranks = append(ranks, c.Rank)
					if tc.mode == TransportQUIC {
						assert.Equal(t, dp.Mode_MODE_QUIC, c.Mode, "mode of the connection of %s to %s", p.name, c.Relay)
					}
				}
				slices.Sort(ranks)
				for i, r := range ranks {
					assert.EqualValues(t, i, r, "ranks of the connections of %s", p.name)
				}
				assert.Equal(t, p.r.addr, p.ta.current().addr, "%s keeps the relay of its config as the primary", p.name)
				for _, i := range tc.want[p.name] {
					assert.Equal(t, 1, p.ta.dials(relays[i-1]), "dials of relay-%d by %s", i, p.name)
				}
			}
		})
	}
}

// TestWantedRelayEnd checks that the connection to a wanted relay stays when
// the last route that names the relay goes, and that the agent dials the relay
// again after the connection ends only while a route or the config names it.
func TestWantedRelayEnd(t *testing.T) {
	cases := []struct {
		name       string
		keepRoute  bool // b stays on relay-2.
		configured bool // The config of a has both relays, with Config.Sessions 2.
		redial     bool
	}{
		{name: "a route names the relay", keepRoute: true, redial: true},
		{name: "no route names the relay"},
		{name: "no route names the relay, which is in the config", configured: true, redial: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			opts := agentOptions{}
			if tc.configured {
				opts.sessions, opts.relays = 2, []identity.Relay{r1.ref(), r2.ref()}
			}
			a := w.agent(t, "a", r1, opts)
			a.attached(t)
			if tc.configured {
				a.attached(t)
			}
			b := w.agent(t, "b", r2, agentOptions{})
			eb := b.attached(t)
			a.hasRoutes(t, eb.prefixes[0])
			if !tc.configured {
				a.attached(t)
			}
			require.Eventually(t, func() bool { return a.dials(r2) == 1 && attachments("a", r2) == 1 }, 5*time.Second, 10*time.Millisecond,
				"attachment of a on relay-2")
			if !tc.keepRoute {
				b.stop()
				require.Eventually(t, func() bool { return !slices.Contains(a.routeSet(), eb.prefixes[0]) }, 5*time.Second, 10*time.Millisecond,
					"route of b")
				require.Never(t, func() bool { return len(a.a.Status().Connections) != 2 || attachments("a", r2) != 1 }, quietWait, 20*time.Millisecond,
					"the connection to relay-2 stays attached")
			}
			for _, qc := range r2.agentConns(a.tr.Conn.LocalAddr(), true) {
				require.NoError(t, qc.CloseWithError(0, "relay closed the session"))
			}
			if tc.redial {
				a.attached(t)
				require.Eventually(t, func() bool { return a.dials(r2) == 2 }, 5*time.Second, 10*time.Millisecond, "dials of relay-2")
				return
			}
			require.Eventually(t, func() bool { return len(a.a.Status().Connections) == 1 }, 5*time.Second, 10*time.Millisecond,
				"the connection to relay-2 ends")
			require.Never(t, func() bool { return a.dials(r2) != 1 }, quietWait, 10*time.Millisecond, "dial of a relay that no route names")
		})
	}
}
