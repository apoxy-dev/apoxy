// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

const ms = time.Millisecond

// TestOneEach checks that entries with one name, or one address and no name,
// or one relay ID in the Welcome at their addresses, count as one relay.
func TestOneEach(t *testing.T) {
	a1, a2, b1 := endpoint{"a", "10.0.0.1:1"}, endpoint{"a", "10.0.0.2:1"}, endpoint{"b", "10.0.0.3:1"}
	n1, n2 := endpoint{"", "10.0.0.4:1"}, endpoint{"", "10.0.0.5:1"}
	cases := []struct {
		name     string
		in, want []endpoint
		welcome  map[string]string // Relay ID of the Welcome at each address.
	}{
		{"no relay", nil, nil, nil},
		{"two relays", []endpoint{a1, b1}, []endpoint{a1, b1}, nil},
		{"two entries with one name and address", []endpoint{a1, a1, b1}, []endpoint{a1, b1}, nil},
		{"two addresses of one relay", []endpoint{a1, b1, a2}, []endpoint{a1, b1}, nil},
		{"no name", []endpoint{n1, n2, n1}, []endpoint{n1, n2}, nil},
		{"two addresses with one Welcome ID", []endpoint{n1, n2, b1}, []endpoint{n1, b1}, map[string]string{n1.addr: "c", n2.addr: "c"}},
		{"a Welcome ID of a named relay", []endpoint{n1, b1}, []endpoint{n1}, map[string]string{n1.addr: "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, (&root{welcome: tc.welcome}).oneEach(tc.in))
		})
	}
}

// TestChoiceWait checks the wait for the other relays after the first answer.
func TestChoiceWait(t *testing.T) {
	cases := []struct {
		name       string
		rtt, hello time.Duration // Of the first answer. Zero is not known.
		want       time.Duration
	}{
		{name: "first relay at 1 ms", rtt: 1 * ms, want: defaultRTTWaitMin},
		{name: "first relay at 15 ms", rtt: 15 * ms, want: 30 * ms},
		{name: "first relay at 30 ms", rtt: 30 * ms, want: defaultRTTWaitMax},
		{name: "first relay with no known time", want: defaultRTTWaitMax},
		{name: "only the time from Hello to Welcome is known", hello: 15 * ms, want: 30 * ms},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &root{a: New(Config{})}
			d := &dialed{stats: statsWithMinRTT(tc.rtt), helloRTT: tc.hello}
			assert.Equal(t, tc.want, r.choiceWait(d))
		})
	}
}

// TestRankDialed checks the order of the relays that answered in the choice,
// with the band of an agent.
func TestRankDialed(t *testing.T) {
	type answer struct{ rtt, hello time.Duration } // Zero is not known.
	cases := []struct {
		name    string
		answers []answer // In the order of the relay list.
		want    []int
	}{
		{name: "times in the band use the order of the list", answers: []answer{{rtt: 12 * ms}, {rtt: 5 * ms}}, want: []int{0, 1}},
		{name: "time above the band", answers: []answer{{rtt: 16 * ms}, {rtt: 5 * ms}}, want: []int{1, 0}},
		{name: "time not known is last", answers: []answer{{}, {rtt: 30 * ms}}, want: []int{1, 0}},
		{name: "time from Hello to Welcome below a QUIC time with a late start",
			answers: []answer{{rtt: 60 * ms, hello: 62 * ms}, {rtt: 110 * ms, hello: 30 * ms}}, want: []int{1, 0}},
		{name: "QUIC time below a late time from Hello to Welcome",
			answers: []answer{{rtt: 60 * ms, hello: 62 * ms}, {rtt: 30 * ms, hello: 110 * ms}}, want: []int{1, 0}},
		{name: "only the time from Hello to Welcome is known", answers: []answer{{rtt: 60 * ms}, {hello: 30 * ms}}, want: []int{1, 0}},
		{name: "three relays in the order of their times", answers: []answer{{rtt: 58 * ms}, {rtt: 20 * ms}, {rtt: 45 * ms}}, want: []int{1, 2, 0}},
		{name: "later places in the band use the order of the list", answers: []answer{{rtt: 20 * ms}, {rtt: 50 * ms}, {rtt: 44 * ms}}, want: []int{0, 1, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &root{a: New(Config{})}
			var got []*dialed
			index := map[*dialed]int{}
			for i, an := range tc.answers {
				d := &dialed{stats: statsWithMinRTT(an.rtt), helloRTT: an.hello}
				got = append(got, d)
				index[d] = i
			}
			// A relay with no answer has no connection.
			got = append(got, nil)
			var order []int
			for _, d := range r.rankDialed(got) {
				order = append(order, index[d])
			}
			assert.Equal(t, tc.want, order)
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
		twice  bool // The list has its one relay two times.
		silent bool // The list starts with a relay that does not answer.
		// swap gives the first two relays the delay of the other after the attach,
		// and ends the attached session after that.
		swap        bool
		first, then int // Relay of the attachment at the start, and at the end.
	}{
		{name: "lowest time wins", delays: []time.Duration{far, 0}, first: 1, then: 1},
		{name: "lowest time of three wins", delays: []time.Duration{2 * far, 0, 20 * ms}, first: 1, then: 1},
		{name: "two entries with one name are one relay", delays: []time.Duration{0}, twice: true, first: 0, then: 0},
		{name: "relay that does not answer", delays: []time.Duration{0}, silent: true, first: 0, then: 0},
		{name: "a new attach chooses again", delays: []time.Duration{far, 0}, swap: true, first: 1, then: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			// The relays write each change at once. With the write interval, the attach takes longer
			// than the dial of the last relay, and the agent keeps that session.
			w.relayCfg.TableWriteInterval = new(time.Duration(0))
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
			a := w.agent(t, "a", nil, agentOptions{mode: TransportAuto, slow: slow, relays: list, rttChoice: !tc.twice})
			a.attached(t)
			if tc.silent {
				assert.Less(t, time.Since(start), openTimeout/2, "the attach does not wait for the dial of the relay with no answer")
			}
			on := func(rc sessionRef) int {
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
				open := 0
				for _, r := range relays {
					open += len(r.agentConns(a.tr.Conn.LocalAddr(), true))
				}
				return len(a.a.Status().Connections) == 1 && open == 1
			}, 10*time.Second, 10*ms, "the sessions to the other relays end")
		})
	}
}

// TestRelayChoiceLatePacket checks the choice when one packet to the nearest
// relay is late: the agent has two times for each relay, and one stays correct.
func TestRelayChoiceLatePacket(t *testing.T) {
	// A pause of the test process adds to the measured time of the near relay,
	// so the far relay is much farther than a pause is long.
	const near, far, late = 26 * ms, 400 * ms, 500 * ms
	cases := []struct {
		name string
		late lateStart
	}{
		{name: "no late packet"},
		// The first QUIC time of the session has the wait of the first packets.
		{name: "path to the nearest relay opens late", late: lateStart{open: late}},
		{name: "late path probe does not change the choice", late: lateStart{probe: late}},
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
				rttChoice: true, rttWait: 5 * time.Second})
			a.attached(t)
			assert.Equal(t, nearRelay.addr, a.current().addr, "relay of the attachment")
		})
	}
}

// statsWithMinRTT returns the stats read of a connection with the lowest RTT rtt.
func statsWithMinRTT(rtt time.Duration) func() quic.ConnectionStats {
	return func() quic.ConnectionStats { return quic.ConnectionStats{MinRTT: rtt} }
}
