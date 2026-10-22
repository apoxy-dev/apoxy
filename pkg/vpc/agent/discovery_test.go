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

// dials returns the Session calls of ta that the relays got, with no extra
// connections.
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
