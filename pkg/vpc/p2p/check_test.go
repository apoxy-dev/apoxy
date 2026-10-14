// SPDX-License-Identifier: AGPL-3.0-only

package p2p

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
)

const testTx = time.Second

// pass gives the next packet of from to to, in a path probe, and returns the
// result of Receive.
func pass(t *testing.T, from, to *Check) bool {
	t.Helper()
	p, err := OpenProbe(from.Append(nil, Probe{SID: testKeys.SID}, &testKeys.Dialer), &testKeys.Dialer)
	require.NoError(t, err)
	require.Len(t, p.BFD, 24)
	return to.Receive(p)
}

// upPair returns the two ends of a check after the packets that make them Up.
func upPair(t *testing.T) (agent, relay *Check) {
	t.Helper()
	agent, relay = NewCheck(RoleAgent, testTx), NewCheck(RoleRelay, testTx)
	t.Cleanup(agent.Close)
	t.Cleanup(relay.Close)
	// Relay: Down to Init. Agent: Down to Up. Relay: Init to Up.
	for _, ends := range [][2]*Check{{agent, relay}, {relay, agent}, {agent, relay}} {
		require.True(t, pass(t, ends[0], ends[1]), "a packet of the start changed no state")
	}
	require.True(t, agent.Up() && relay.Up())
	require.False(t, pass(t, agent, relay), "a packet between two Up ends changed a state")
	return agent, relay
}

// TestCheckLost checks when an end of the check reports the path as lost.
func TestCheckLost(t *testing.T) {
	const detect = bfdl.DefaultDetectMult * testTx
	cases := []struct {
		name string
		// run returns the end to ask and the time after its packet.
		run  func(t *testing.T) (*Check, time.Duration)
		lost bool
	}{
		{name: "packet now", run: func(t *testing.T) (*Check, time.Duration) {
			_, r := upPair(t)
			return r, 0
		}},
		{name: "silence of the detect time", run: func(t *testing.T) (*Check, time.Duration) {
			_, r := upPair(t)
			return r, detect
		}},
		{name: "silence above the detect time", lost: true, run: func(t *testing.T) (*Check, time.Duration) {
			_, r := upPair(t)
			return r, detect + time.Millisecond
		}},
		{name: "other end is Down", lost: true, run: func(t *testing.T) (*Check, time.Duration) {
			a, r := upPair(t)
			require.True(t, a.Lost(a.s.LastRx().Add(detect+time.Millisecond)))
			// A packet of a Down end makes the other end Down.
			require.True(t, pass(t, a, r))
			return r, 0
		}},
		{name: "new end with no packet", lost: true, run: func(t *testing.T) (*Check, time.Duration) {
			c := NewCheck(RoleRelay, testTx)
			t.Cleanup(c.Close)
			return c, detect + time.Millisecond
		}},
		{name: "end that is not Up yet", run: func(t *testing.T) (*Check, time.Duration) {
			a, r := NewCheck(RoleAgent, testTx), NewCheck(RoleRelay, testTx)
			t.Cleanup(a.Close)
			t.Cleanup(r.Close)
			require.True(t, pass(t, a, r))
			return r, detect
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			timeouts := testutil.ToFloat64(bfdl.BFDDetectTimeouts.WithLabelValues(RoleRelay))
			c, after := tc.run(t)
			last := c.s.LastRx()
			if last.IsZero() {
				last = c.start
			}
			assert.Equal(t, tc.lost, c.Lost(last.Add(after)))
			assert.Equal(t, tc.lost, c.Lost(last), "a lost path must stay lost")
			if tc.lost {
				assert.False(t, c.Up(), "the end of a lost path is Up")
			}
			if after > 0 && tc.lost {
				assert.Equal(t, timeouts+1, testutil.ToFloat64(bfdl.BFDDetectTimeouts.WithLabelValues(RoleRelay)))
			}
		})
	}
}

// TestCheckMetrics checks that a check counts its session in the gauge of its
// state, and its packets.
func TestCheckMetrics(t *testing.T) {
	up := func() float64 { return testutil.ToFloat64(bfdl.BFDSessionsActive.WithLabelValues(RoleRelay, "Up")) }
	down := func() float64 { return testutil.ToFloat64(bfdl.BFDSessionsActive.WithLabelValues(RoleRelay, "Down")) }
	rx := func() float64 { return testutil.ToFloat64(bfdl.BFDPacketsRx.WithLabelValues(RoleRelay)) }
	tx := func() float64 { return testutil.ToFloat64(bfdl.BFDPacketsTx.WithLabelValues(RoleRelay)) }
	up0, down0, rx0, tx0 := up(), down(), rx(), tx()
	_, r := upPair(t)
	assert.Equal(t, up0+1, up())
	assert.Equal(t, down0, down())
	assert.Equal(t, rx0+3, rx(), "packets of the agent end")
	assert.Equal(t, tx0+1, tx(), "packets of the relay end")
	require.True(t, r.Lost(r.s.LastRx().Add(time.Hour)))
	assert.Equal(t, up0, up())
	assert.Equal(t, down0+1, down())
	r.Close()
	r.Close()
	assert.Equal(t, down0, down())
	assert.False(t, r.Receive(Probe{BFD: make([]byte, 3)}), "a short BFD packet changed the state")
}
