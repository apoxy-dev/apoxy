// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestPSPRetry checks that a session whose first probe failed changes to PSP mode after
// two probes pass, with the same address and open TCP connection, and stays on QUIC when it fails.
func TestPSPRetry(t *testing.T) {
	retry := [3]time.Duration{100 * time.Millisecond, 400 * time.Millisecond, 300 * time.Millisecond}
	cases := []struct {
		name   string
		budget int32 // Probes that get a reply. Zero means each probe.
		drain  bool  // The relay drains before the probes pass.
		// path is the largest inner packet that the path carries as PSP after the
		// attach, on a VPC with an MTU of 1400 B. Zero means no limit.
		path int
		// probes is the number of probes after which the agent made its decision,
		// for a case that stays in QUIC mode.
		probes int32
	}{
		{name: "two probes pass"},
		// A failed probe sends 3 probes. The probe after them is the next retry.
		{name: "one probe passes", budget: 1, probes: 1 + 3 + 1},
		{name: "relay drains", drain: true, probes: 2},
		{name: "path carries 1280 B but not 1308 B", path: psp.QUICMTU - 1, probes: 3 + 1},
		{name: "path carries 1308 B", path: psp.QUICMTU},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			if tc.path != 0 {
				w.mtu = 1400
			}
			r := w.relay(t, "relay-1")
			conn := &lossyConn{}
			conn.limitProbes.Store(true)
			a, b := w.agent(t, "a", r, agentOptions{conn: conn, tcp: true, pspRetry: retry}), w.agent(t, "b", r, agentOptions{tcp: true})
			ea, eb := a.attached(t), b.attached(t)
			if tc.path != 0 {
				require.Greater(t, a.binding().DeviceMTU(), psp.QUICMTU)
				conn.max.Store(int32(tc.path + pspwire.Overhead))
			}
			require.Equal(t, dp.Mode_MODE_QUIC, a.a.Status().Mode)
			require.Eventually(t, func() bool {
				return a.a.Status().Reason == dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT
			}, 5*time.Second, 5*time.Millisecond, "the first probe did not fail")
			serveTCP(t, b.stack, eb.addr, 9000)
			c := dialTCP(t, a, eb.addr, 9000)
			roundTrip(t, c, "in QUIC mode")

			rc, bind, id := a.current(), a.binding(), a.a.Attachments()[0].ID
			if tc.drain {
				drain(t, r, nil)
				require.Eventually(t, func() bool { return stateOf(a, rc) == stDraining }, 5*time.Second, 5*time.Millisecond)
			}
			sent, psp := conn.probes.Load(), pspPackets(bind.LanePackets())
			if tc.budget != 0 {
				conn.probeBudget.Store(tc.budget)
			} else {
				conn.limitProbes.Store(false)
			}
			mode := func() dp.Mode { return a.a.Status().Mode }
			same := func(msg string) {
				t.Helper()
				roundTrip(t, c, msg)
				sameSession(t, rc, a.current(), "the agent has the same relay session")
				assert.Empty(t, a.attach, "the agent attached again")
				assert.Equal(t, ea.addr, a.a.Status().Connections[0].Address)
				assert.Equal(t, id, a.a.Attachments()[0].ID)
			}

			if tc.probes != 0 {
				require.Eventually(t, func() bool { return conn.probes.Load() >= sent+tc.probes }, 10*time.Second, 5*time.Millisecond)
				require.Never(t, func() bool { return mode() != dp.Mode_MODE_QUIC }, 500*time.Millisecond, 20*time.Millisecond, "the session changed to PSP mode")
				assert.Zero(t, pspPackets(bind.LanePackets())-psp, "PSP packets in QUIC mode")
				same("with no change")
				return
			}

			require.Eventually(t, func() bool { return mode() == dp.Mode_MODE_PSP }, 15*time.Second, 5*time.Millisecond)
			assert.Equal(t, dp.FallbackReason_FALLBACK_REASON_UNSPECIFIED, a.a.Status().Reason)
			same("after the change")
			assert.Same(t, bind, a.binding())
			if tc.path != 0 {
				assert.Equal(t, tc.path, bind.ClampMTU(), "TCP MSS clamp for the packets that the path carries")
			}
			// The send counts a packet after the socket write, which can be after the answer.
			assert.Eventually(t, func() bool { return pspPackets(bind.LanePackets()) > psp }, 2*time.Second, 5*time.Millisecond,
				"PSP packets after the change")
			require.Eventually(t, func() bool { return len(r.agentConns(a.tr.Conn.LocalAddr(), true)) == 1 }, 5*time.Second, 10*time.Millisecond,
				"the extra connections close in PSP mode")
			same("in PSP mode")
		})
	}
}

// TestSessionStart checks the start of a session: QUIC mode at once, then PSP
// mode after one probe passes. Only a session in PSP mode sends BFD packets.
func TestSessionStart(t *testing.T) {
	cases := []struct {
		name   string
		mode   TransportMode
		drop   bool // The PSP port of the relay drops each packet.
		want   dp.Mode
		reason dp.FallbackReason
	}{
		{name: "PSP path passes", want: dp.Mode_MODE_PSP},
		{name: "PSP port drops packets", drop: true, want: dp.Mode_MODE_QUIC, reason: dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT},
		{name: "QUIC mode in the config", mode: TransportQUIC, want: dp.Mode_MODE_QUIC, reason: dp.FallbackReason_FALLBACK_REASON_CONFIG},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			conn := &lossyConn{}
			conn.limitProbes.Store(tc.drop)
			a := w.agent(t, "a", r, agentOptions{conn: conn, mode: tc.mode, tcp: true, quicStart: true, pspRetry: [3]time.Duration{time.Minute}})
			b := w.agent(t, "b", r, agentOptions{tcp: true})
			ea, eb := a.attached(t), b.attached(t)
			rc, id := a.current(), a.a.Attachments()[0].ID
			assert.Less(t, a.a.Status().Setup, probeWait, "the attach waited for the result of the PSP probe")
			serveTCP(t, b.stack, eb.addr, 9000)
			c := dialTCP(t, a, eb.addr, 9000)
			roundTrip(t, c, "after the attach")

			require.Eventually(t, func() bool {
				st := a.a.Status()
				return st.Mode == tc.want && st.Reason == tc.reason
			}, 5*time.Second, 5*time.Millisecond, "data mode and reason")
			sent := conn.probes.Load()
			if tc.want == dp.Mode_MODE_PSP {
				require.Eventually(t, func() bool { return conn.probes.Load() > sent }, 2*checkTx, 5*time.Millisecond,
					"a session in PSP mode sent no BFD packet")
			} else {
				require.Never(t, func() bool { return conn.probes.Load() > sent }, checkTx+checkTx/2, 25*time.Millisecond,
					"a session in QUIC mode sent a probe")
			}
			if tc.mode == TransportQUIC {
				assert.Zero(t, sent, "probes of an agent with QUIC mode in its config")
			}
			st := a.a.Status()
			assert.Equal(t, tc.want, st.Mode)
			sameSession(t, rc, a.current(), "the agent has the same relay session")
			assert.Empty(t, a.attach, "the agent attached again")
			assert.Equal(t, ea.addr, st.Connections[0].Address)
			assert.Equal(t, id, a.a.Attachments()[0].ID)
			roundTrip(t, c, "at the end")
		})
	}
}
