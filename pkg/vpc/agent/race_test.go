// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

const ms = time.Millisecond

// TestOneEach checks that entries with one name, or one address and no name,
// count as one relay.
func TestOneEach(t *testing.T) {
	a1, a2, b1 := endpoint{"a", "10.0.0.1:1"}, endpoint{"a", "10.0.0.2:1"}, endpoint{"b", "10.0.0.3:1"}
	n1, n2 := endpoint{"", "10.0.0.4:1"}, endpoint{"", "10.0.0.5:1"}
	cases := []struct {
		name     string
		in, want []endpoint
	}{
		{"no relay", nil, nil},
		{"two relays", []endpoint{a1, b1}, []endpoint{a1, b1}},
		{"two entries with one name and address", []endpoint{a1, a1, b1}, []endpoint{a1, b1}},
		{"two addresses of one relay", []endpoint{a1, b1, a2}, []endpoint{a1, b1}},
		{"no name", []endpoint{n1, n2, n1}, []endpoint{n1, n2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, oneEach(tc.in))
		})
	}
}

// fakeRelay is a relay of TestChoose. Its dial uses no network.
type fakeRelay struct {
	ready    time.Duration // Time from the dial to the wait before Hello.
	rtt      time.Duration
	fails    bool // The dial fails at ready.
	silent   bool // The relay does not answer.
	noHello  bool // Hello fails after the choice.
	sameName bool // The entry has the name and the address of the entry before it.
}

// TestChoose checks which relay takes the attachment, the order of the spares
// and the time of the choice, with the band and the wait of an agent.
func TestChoose(t *testing.T) {
	cases := []struct {
		name   string
		relays []fakeRelay
		won    int           // Index of the relay that takes the attachment. -1 is an error.
		spares []int         // The other sessions, in the order that choose gives them.
		at     time.Duration // Time of the choice.
		failed int
	}{
		{name: "lowest time wins", relays: []fakeRelay{{ready: 60 * ms, rtt: 60 * ms}, {ready: 5 * ms, rtt: 5 * ms}},
			won: 1, spares: []int{0}, at: 5*ms + rttWindow},
		{name: "times in the band use the order of the list", relays: []fakeRelay{{ready: 12 * ms, rtt: 12 * ms}, {ready: 5 * ms, rtt: 5 * ms}},
			won: 0, spares: []int{1}, at: 12 * ms},
		{name: "time above the band", relays: []fakeRelay{{ready: 16 * ms, rtt: 16 * ms}, {ready: 5 * ms, rtt: 5 * ms}},
			won: 1, spares: []int{0}, at: 16 * ms},
		{name: "relays at 12 ms, 5 ms and 150 ms", relays: []fakeRelay{{ready: 12 * ms, rtt: 12 * ms}, {ready: 5 * ms, rtt: 5 * ms}, {ready: 150 * ms, rtt: 150 * ms}},
			won: 0, spares: []int{1, 2}, at: 5*ms + rttWindow},
		{name: "spare is the second lowest", relays: []fakeRelay{{ready: 44 * ms, rtt: 44 * ms}, {ready: 5 * ms, rtt: 5 * ms}, {ready: 30 * ms, rtt: 30 * ms}},
			won: 1, spares: []int{2, 0}, at: 44 * ms},
		{name: "spares in the band use the order of the list", relays: []fakeRelay{{ready: 5 * ms, rtt: 5 * ms}, {ready: 30 * ms, rtt: 30 * ms}, {ready: 24 * ms, rtt: 24 * ms}},
			won: 0, spares: []int{1, 2}, at: 30 * ms},
		{name: "late session opens before the session of the choice", relays: []fakeRelay{{ready: 5 * ms, rtt: 60 * ms}, {ready: 50 * ms, rtt: 2 * ms}, {ready: 6 * ms, rtt: 80 * ms}},
			won: 0, spares: []int{2, 1}, at: 5*ms + rttWindow},
		{name: "relay that does not answer", relays: []fakeRelay{{silent: true}, {ready: 5 * ms, rtt: 5 * ms}},
			won: 1, at: 5*ms + rttWindow},
		{name: "relay that fails", relays: []fakeRelay{{ready: 3 * ms, fails: true}, {ready: 5 * ms, rtt: 5 * ms}},
			won: 1, at: 5 * ms, failed: 1},
		{name: "all relays fail", relays: []fakeRelay{{ready: 3 * ms, fails: true}, {ready: 5 * ms, fails: true}},
			won: -1, failed: 2},
		{name: "Hello fails on the relay of the choice", relays: []fakeRelay{{ready: 5 * ms, rtt: 5 * ms, noHello: true}, {ready: 8 * ms, rtt: 8 * ms}},
			won: 1, at: 8 * ms, failed: 1},
		{name: "Hello fails, and the other relay answers late", relays: []fakeRelay{{ready: 5 * ms, rtt: 5 * ms, noHello: true}, {ready: 90 * ms, rtt: 90 * ms}},
			won: 1, at: 5*ms + rttWindow, failed: 1},
		{name: "time not known is last", relays: []fakeRelay{{ready: 5 * ms}, {ready: 8 * ms, rtt: 30 * ms}},
			won: 1, spares: []int{0}, at: 8 * ms},
		{name: "two entries with one name are one relay", relays: []fakeRelay{{ready: 5 * ms, rtt: 5 * ms}, {sameName: true}, {ready: 8 * ms, rtt: 8 * ms}},
			won: 0, spares: []int{2}, at: 8 * ms},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := &Agent{rttBand: rttBand, rttWindow: rttWindow}
				var eps []endpoint
				index := map[string]int{}
				for i := range tc.relays {
					e := endpoint{id: string(rune('a' + i)), addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 1).String()}
					if tc.relays[i].sameName {
						e = eps[i-1]
					} else {
						index[e.addr] = i
					}
					eps = append(eps, e)
				}
				// choice is the relay that the agent chooses. Its Hello can fail.
				choice := tc.won
				for i, r := range tc.relays {
					if r.noHello {
						choice = i
					}
				}
				start := time.Now()
				var mu sync.Mutex
				var chosen []time.Duration // Time of the choice, as each session sees it.
				var dials atomic.Int32
				dial := func(ctx context.Context, e endpoint, spare func(*relayConn) bool) (*relayConn, error) {
					dials.Add(1)
					r := tc.relays[index[e.addr]]
					if r.silent {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					time.Sleep(r.ready)
					if r.fails {
						return nil, errors.New("relay refused the session")
					}
					rc := &relayConn{ep: e, addr: e.addr, rtt: new(atomic.Int64)}
					rc.rtt.Store(int64(r.rtt))
					isSpare := spare(rc)
					mu.Lock()
					chosen = append(chosen, time.Since(start))
					mu.Unlock()
					if r.noHello {
						return nil, errors.New("relay closed the session")
					}
					// Hello and Welcome take one round trip.
					time.Sleep(r.rtt)
					assert.Equal(t, index[e.addr] != choice, isSpare, "spare in Hello of relay %s", e.id)
					return rc, nil
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				won, others, failed, err := a.choose(ctx, eps, dial)
				if tc.won < 0 {
					require.Error(t, err)
					assert.Nil(t, won)
					assert.Equal(t, tc.failed, failed)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, eps[tc.won], won.ep, "relay of the attachment")
				assert.Equal(t, tc.failed, failed, "relays that failed")
				mu.Lock()
				assert.Equal(t, tc.at, chosen[0], "time of the choice")
				mu.Unlock()
				// The dial of a relay that does not answer ends with the context.
				defer time.AfterFunc(time.Second, cancel).Stop()
				var spares []int
				others(func(rc *relayConn) { spares = append(spares, index[rc.addr]) })
				assert.Equal(t, tc.spares, spares, "the other sessions")
				assert.EqualValues(t, len(index), dials.Load(), "one dial for each relay")
			})
		})
	}
}

// TestRelayChoice checks the choice with relays: the agent attaches to the relay
// with the lowest round-trip time, and it does not move when the times change.
func TestRelayChoice(t *testing.T) {
	// far is above the band and the wait of the choice, with the noise of a loaded host.
	const far = 150 * ms
	cases := []struct {
		name     string
		sessions int
		// delays has the delay of the packets to each relay at the start.
		delays []time.Duration
		twice  bool // The list has the first relay two times, and the relays are equal.
		silent bool // The list starts with a relay that does not answer.
		// swap gives the first two relays the delay of the other after the attach,
		// and reconnect ends the attached session after that.
		swap, reconnect bool
		first, then     int // Relay of the attachment at the start, and at the end.
		spare           int // Relay of the spare at the end. -1 is no spare.
	}{
		{name: "lowest time wins, the other relay is the spare", sessions: 2, delays: []time.Duration{far, 0}, first: 1, then: 1, spare: 0},
		{name: "the spare is the second lowest", sessions: 2, delays: []time.Duration{2 * far, 0, 20 * ms}, first: 1, then: 1, spare: 2},
		{name: "two entries with one name are one relay", sessions: 3, delays: []time.Duration{0, 0}, twice: true, first: 0, then: 0, spare: 1},
		{name: "relay that does not answer", sessions: 1, delays: []time.Duration{0}, silent: true, first: 0, then: 0, spare: -1},
		{name: "no move after the attach when the times change", sessions: 2, delays: []time.Duration{far, 0}, swap: true, first: 1, then: 1, spare: 0},
		{name: "a new attach with no spare chooses again", sessions: 1, delays: []time.Duration{far, 0}, swap: true, reconnect: true, first: 1, then: 0, spare: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			slow := &slowConn{}
			var relays []*testRelay
			var list []identity.Relay
			if tc.silent {
				// No relay reads this socket.
				list = append(list, identity.Relay{ID: "relay-0", Addresses: []string{loopback(t).LocalAddr().String()}})
			}
			for i, d := range tc.delays {
				r := w.relay(t, "relay-"+string(rune('1'+i)))
				slow.set(r, d)
				relays = append(relays, r)
				list = append(list, r.ref())
				if tc.twice && i == 0 {
					list = append(list, r.ref())
				}
			}
			start := time.Now()
			a := w.agent(t, "a", nil, agentOptions{mode: TransportPSP, slow: slow, relays: list, sessions: tc.sessions, rttChoice: !tc.twice})
			a.attached(t)
			if tc.silent {
				assert.Less(t, time.Since(start), openTimeout/2, "the attach does not wait for the dial of the relay with no answer")
			}
			on := func(rc *relayConn) int {
				if rc == nil {
					return -1
				}
				for i, r := range relays {
					if r.addr == rc.addr {
						return i
					}
				}
				return -2
			}
			first := a.current()
			require.Equal(t, tc.first, on(first), "relay of the attachment")
			sessions := func() (dials, conns int) {
				a.a.mu.Lock()
				defer a.a.mu.Unlock()
				return len(a.a.dialing), len(a.a.conns)
			}
			if !tc.silent {
				// A relay with a dial that runs is not in the next choice.
				require.Eventually(t, func() bool { d, _ := sessions(); return d == 0 }, 10*time.Second, 10*ms, "the dials end")
			}
			if tc.swap {
				slow.set(relays[0], tc.delays[1])
				slow.set(relays[1], tc.delays[0])
			}
			if tc.reconnect {
				a.reconnect()
				a.attached(t)
			}
			require.Eventually(t, func() bool { return on(a.spare()) == tc.spare }, 10*time.Second, 10*ms, "relay of the spare")
			if tc.swap && !tc.reconnect {
				// The spare check runs with the new times, and the attachment stays.
				a.a.wakeSpares()
				require.Never(t, func() bool { return a.current() != first }, 200*ms, 10*ms, "the attachment stays")
			}
			assert.Equal(t, tc.then, on(a.current()), "relay of the attachment at the end")
			require.Eventually(t, func() bool { _, c := sessions(); return c == min(tc.sessions, len(relays)) },
				10*time.Second, 10*ms, "relay sessions")
		})
	}
}
