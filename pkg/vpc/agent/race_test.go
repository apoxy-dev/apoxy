// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
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

// fakeRelay is a relay of TestChoose. Its dial uses no network. probe is the
// round-trip time of its path probe, and zero is no probe.
type fakeRelay struct {
	open     time.Duration // Time from the dial to the open session.
	rtt      time.Duration
	probe    time.Duration
	fails    bool // The dial fails at open.
	silent   bool // The relay does not answer.
	sameName bool // The entry has the name and the address of the entry before it.
}

// TestChoose checks the order of the sessions that choose gives and the time of
// the choice, with the band and the wait of an agent.
func TestChoose(t *testing.T) {
	cases := []struct {
		name   string
		relays []fakeRelay
		want   []int         // The relays of the sessions, best first.
		at     time.Duration // Time of the choice.
		failed int
	}{
		{name: "lowest time is first, a late relay is not in the choice", relays: []fakeRelay{{open: 60 * ms, rtt: 60 * ms}, {open: 5 * ms, rtt: 5 * ms}},
			want: []int{1}, at: 5*ms + rttWaitMin},
		{name: "times in the band use the order of the list", relays: []fakeRelay{{open: 12 * ms, rtt: 12 * ms}, {open: 5 * ms, rtt: 5 * ms}},
			want: []int{0, 1}, at: 12 * ms},
		{name: "time above the band", relays: []fakeRelay{{open: 16 * ms, rtt: 16 * ms}, {open: 5 * ms, rtt: 5 * ms}},
			want: []int{1, 0}, at: 16 * ms},
		{name: "first relay at 1 ms, the other relay does not answer", relays: []fakeRelay{{silent: true}, {open: 1 * ms, rtt: 1 * ms}},
			want: []int{1}, at: 1*ms + rttWaitMin},
		{name: "first relay at 15 ms, the other relay does not answer", relays: []fakeRelay{{silent: true}, {open: 15 * ms, rtt: 15 * ms}},
			want: []int{1}, at: 15*ms + 30*ms},
		{name: "first relay at 30 ms, the other relay does not answer", relays: []fakeRelay{{silent: true}, {open: 30 * ms, rtt: 30 * ms}},
			want: []int{1}, at: 30*ms + rttWaitMax},
		{name: "first relay with no known time, the other relay does not answer", relays: []fakeRelay{{silent: true}, {open: 5 * ms}},
			want: []int{1}, at: 5*ms + rttWaitMax},
		{name: "time not known is last", relays: []fakeRelay{{open: 5 * ms}, {open: 8 * ms, rtt: 30 * ms}},
			want: []int{1, 0}, at: 8 * ms},
		{name: "path probe time below a QUIC time with a late packet", relays: []fakeRelay{{open: 60 * ms, rtt: 60 * ms, probe: 62 * ms}, {open: 50 * ms, rtt: 110 * ms, probe: 30 * ms}},
			want: []int{1, 0}, at: 60 * ms},
		{name: "QUIC time below the time of a late path probe", relays: []fakeRelay{{open: 60 * ms, rtt: 60 * ms, probe: 62 * ms}, {open: 50 * ms, rtt: 30 * ms, probe: 110 * ms}},
			want: []int{1, 0}, at: 60 * ms},
		{name: "three relays in the order of their times", relays: []fakeRelay{{open: 58 * ms, rtt: 58 * ms}, {open: 20 * ms, rtt: 20 * ms}, {open: 45 * ms, rtt: 45 * ms}},
			want: []int{1, 2, 0}, at: 58 * ms},
		{name: "later places in the band use the order of the list", relays: []fakeRelay{{open: 20 * ms, rtt: 20 * ms}, {open: 50 * ms, rtt: 50 * ms}, {open: 44 * ms, rtt: 44 * ms}},
			want: []int{0, 1, 2}, at: 50 * ms},
		{name: "relay with the lowest time answers after the wait", relays: []fakeRelay{{open: 5 * ms, rtt: 20 * ms}, {open: 60 * ms, rtt: 2 * ms}, {open: 6 * ms, rtt: 30 * ms}},
			want: []int{0, 2}, at: 5*ms + rttWaitMax},
		{name: "relay that fails", relays: []fakeRelay{{open: 3 * ms, fails: true}, {open: 5 * ms, rtt: 5 * ms}},
			want: []int{1}, at: 5 * ms, failed: 1},
		{name: "all relays fail", relays: []fakeRelay{{open: 3 * ms, fails: true}, {open: 5 * ms, fails: true}},
			at: 5 * ms, failed: 2},
		{name: "two entries with one name are one relay", relays: []fakeRelay{{open: 5 * ms, rtt: 5 * ms}, {sameName: true}, {open: 8 * ms, rtt: 8 * ms}},
			want: []int{0, 2}, at: 8 * ms},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := &Agent{rttBand: rttBand, rttWaitMin: rttWaitMin, rttWaitMax: rttWaitMax}
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
				var dials atomic.Int32
				dial := func(ctx context.Context, e endpoint) (*relayConn, error) {
					dials.Add(1)
					r := tc.relays[index[e.addr]]
					if r.silent {
						r.open = time.Hour
					}
					// The choice stops the dial of a relay that answers late.
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(r.open):
					}
					if r.fails {
						return nil, errors.New("relay refused the session")
					}
					rc := &relayConn{ep: e, addr: e.addr, rtt: new(atomic.Int64)}
					rc.rtt.Store(int64(r.rtt))
					rc.probeRTT.Store(int64(r.probe))
					return rc, nil
				}
				start := time.Now()
				conns, failed, err := a.choose(t.Context(), eps, dial)
				assert.Equal(t, tc.at, time.Since(start), "time of the choice")
				assert.Equal(t, tc.failed, failed, "relays that failed")
				assert.Equal(t, tc.failed > 0, err != nil, "error of the relays that failed: %v", err)
				var got []int
				for _, rc := range conns {
					got = append(got, index[rc.addr])
				}
				assert.Equal(t, tc.want, got, "relays of the sessions")
				assert.EqualValues(t, len(index), dials.Load(), "one dial for each relay")
			})
		})
	}
}

// TestRelayChoice checks the choice with relays: the agent attaches to the relay
// with the lowest round-trip time, and it ends the sessions to the other relays.
func TestRelayChoice(t *testing.T) {
	// far is above the band and the wait of the choice, with the noise of a loaded host.
	const far = 150 * ms
	cases := []struct {
		name string
		// delays has the delay of the packets to each relay at the start.
		delays []time.Duration
		twice  bool // The list has the first relay two times, and the relays are equal.
		silent bool // The list starts with a relay that does not answer.
		// swap gives the first two relays the delay of the other after the attach,
		// and ends the attached session after that.
		swap        bool
		first, then int // Relay of the attachment at the start, and at the end.
	}{
		{name: "lowest time wins", delays: []time.Duration{far, 0}, first: 1, then: 1},
		{name: "lowest time of three wins", delays: []time.Duration{2 * far, 0, 20 * ms}, first: 1, then: 1},
		{name: "two entries with one name are one relay", delays: []time.Duration{0, 0}, twice: true, first: 0, then: 0},
		{name: "relay that does not answer", delays: []time.Duration{0}, silent: true, first: 0, then: 0},
		{name: "a new attach chooses again", delays: []time.Duration{far, 0}, swap: true, first: 1, then: 0},
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
			a := w.agent(t, "a", nil, agentOptions{mode: TransportPSP, slow: slow, relays: list, rttChoice: !tc.twice})
			a.attached(t)
			if tc.silent {
				assert.Less(t, time.Since(start), openTimeout/2, "the attach does not wait for the dial of the relay with no answer")
			}
			on := func(rc *relayConn) int {
				return slices.IndexFunc(relays, func(r *testRelay) bool { return r.addr == rc.addr })
			}
			require.Equal(t, tc.first, on(a.current()), "relay of the attachment")
			if tc.swap {
				slow.set(relays[0], tc.delays[1])
				slow.set(relays[1], tc.delays[0])
				a.reconnect()
				a.attached(t)
			}
			assert.Equal(t, tc.then, on(a.current()), "relay of the attachment at the end")
			require.Eventually(t, func() bool {
				a.a.mu.Lock()
				defer a.a.mu.Unlock()
				return len(a.a.conns) == 1
			}, 10*time.Second, 10*ms, "the sessions to the other relays end")
		})
	}
}

// TestRelayChoiceLatePacket checks the choice when one packet to the nearest
// relay is late: the agent has two times for each relay, and one stays correct.
func TestRelayChoiceLatePacket(t *testing.T) {
	const near, far, late = 26 * ms, 80 * ms, 150 * ms
	cases := []struct {
		name string
		late lateStart
	}{
		{name: "no late packet"},
		// The first QUIC time of the session has the wait of the first packets.
		{name: "path to the nearest relay opens late", late: lateStart{open: late}},
		{name: "path probe to the nearest relay is late", late: lateStart{probe: late}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			slow := &slowConn{}
			farRelay, nearRelay := w.relay(t, "relay-far"), w.relay(t, "relay-near")
			slow.set(farRelay, far)
			slow.set(nearRelay, near)
			slow.setLate(nearRelay, tc.late)
			// The wait is long, so the two relays are in the choice on a loaded host.
			a := w.agent(t, "a", nil, agentOptions{slow: slow, relays: []identity.Relay{farRelay.ref(), nearRelay.ref()},
				rttChoice: true, rttWait: 2 * time.Second})
			a.attached(t)
			assert.Equal(t, nearRelay.addr, a.current().addr, "relay of the attachment")
		})
	}
}
