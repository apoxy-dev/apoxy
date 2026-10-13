// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// Faults of rekeyClient.
const (
	rekeyRefused int32 = iota + 1 // The relay refuses each SPI.
	rekeyFails                    // The call fails.
)

// rekeyClient is the relay client of a session. It keeps the time of each
// Rekey call, and it answers the call itself while it has a fault.
type rekeyClient struct {
	dp.RelayClient
	fault atomic.Int32

	mu    sync.Mutex
	calls []time.Time
}

func (c *rekeyClient) Rekey(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	c.mu.Lock()
	c.calls = append(c.calls, time.Now())
	c.mu.Unlock()
	switch c.fault.Load() {
	case rekeyRefused:
		req, err := keyproto.FromProto(in)
		if err != nil {
			return nil, err
		}
		res := &dp.KeysResponse{}
		for _, sa := range req.SAs {
			res.RefusedSpis = append(res.RefusedSpis, sa.SPI)
		}
		return res, nil
	case rekeyFails:
		return nil, rpc.Errorf(rpc.Unavailable, "relay has no PSP bridge")
	}
	return c.RelayClient.Rekey(ctx, in)
}

func (c *rekeyClient) times() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.calls...)
}

// TestPSPRetry checks that a session in QUIC mode changes to PSP mode after two probes
// pass, with the same address and open TCP connection, and stays on QUIC when it fails.
func TestPSPRetry(t *testing.T) {
	oldMin, oldMax, oldNext := pspRetryMin, pspRetryMax, pspRetryNext
	pspRetryMin, pspRetryMax, pspRetryNext = 100*time.Millisecond, 400*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { pspRetryMin, pspRetryMax, pspRetryNext = oldMin, oldMax, oldNext })
	cases := []struct {
		name   string
		budget int32 // Probes that get a reply. Zero means each probe.
		fault  int32 // Fault of the first Rekey calls.
		burst  int   // Rekey calls of one change that fails.
		drain  bool  // The relay drains before the probes pass.
		// path is the largest inner packet that the path carries as PSP after the
		// attach, on a VPC with an MTU of 1400 B. Zero means no limit.
		path int
		// probes is the number of probes after which the agent made its decision,
		// for a case with no Rekey call.
		probes int32
	}{
		{name: "two probes pass"},
		// A failed probe sends 3 probes. The probe after them is the next retry.
		{name: "one probe passes", budget: 1, probes: 1 + 3 + 1},
		{name: "relay refuses the keys", fault: rekeyRefused, burst: maxRefusals},
		{name: "Rekey call fails", fault: rekeyFails, burst: 1},
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
			a, b := w.agent(t, "a", r, agentOptions{conn: conn, tcp: true}), w.agent(t, "b", r, agentOptions{tcp: true})
			ea, eb := a.attached(t), b.attached(t)
			if tc.path != 0 {
				require.Greater(t, a.binding().DeviceMTU(), psp.QUICMTU)
				conn.max.Store(int32(tc.path + pspwire.Overhead))
			}
			st := a.a.Status()
			require.Equal(t, dp.Mode_MODE_QUIC, st.Mode)
			require.Equal(t, dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT, st.Reason)
			serveTCP(t, b.stack, eb.addr, 9000)
			c := dialTCP(t, a, eb.addr, 9000)
			roundTrip(t, c, "in QUIC mode")

			rc, bind, inQUIC := a.current(), a.binding(), onlyPeer(t, a.a)
			require.True(t, inQUIC.quic)
			rk := &rekeyClient{RelayClient: rc.c}
			rk.fault.Store(tc.fault)
			a.a.mu.Lock()
			rc.c = rk
			a.a.mu.Unlock()
			if tc.drain {
				drain(t, r, nil)
				require.Eventually(t, func() bool { return stateOf(a, rc) == connDraining }, 5*time.Second, 5*time.Millisecond)
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
				assert.Same(t, rc, a.current(), "the agent has the same relay session")
				assert.Empty(t, a.attach, "the agent attached again")
				assert.Equal(t, ea.addr, a.a.Status().Connections[0].Address)
				assert.Equal(t, rc.claims.GetAttachmentId(), a.a.Attachments()[0].ID)
			}

			if tc.probes != 0 {
				require.Eventually(t, func() bool { return conn.probes.Load() >= sent+tc.probes }, 10*time.Second, 5*time.Millisecond)
				require.Never(t, func() bool { return len(rk.times()) > 0 }, 500*time.Millisecond, 20*time.Millisecond, "the agent made a Rekey call")
				assert.Equal(t, dp.Mode_MODE_QUIC, mode())
				same("with no change")
				return
			}
			if tc.fault != 0 {
				// The second change starts after the backoff and two more probes.
				require.Eventually(t, func() bool { return len(rk.times()) > tc.burst }, 15*time.Second, 5*time.Millisecond)
				calls := rk.times()
				assert.GreaterOrEqual(t, calls[tc.burst].Sub(calls[0]), pspRetryMin+pspRetryNext, "time to the next change")
				assert.Equal(t, dp.Mode_MODE_QUIC, mode())
				assert.Zero(t, pspPackets(bind.LanePackets())-psp, "PSP packets after a change that failed")
				same("after the change that failed")
				rk.fault.Store(0)
			}

			require.Eventually(t, func() bool { return mode() == dp.Mode_MODE_PSP }, 15*time.Second, 5*time.Millisecond)
			assert.Equal(t, dp.FallbackReason_FALLBACK_REASON_UNSPECIFIED, a.a.Status().Reason)
			require.Eventually(t, func() bool { return inQUIC.qc.Context().Err() != nil }, 5*time.Second, 5*time.Millisecond,
				"the peer session of QUIC mode stays open")
			same("after the change")
			assert.Same(t, bind, a.binding())
			if tc.path != 0 {
				assert.Equal(t, tc.path, bind.ClampMTU(), "TCP MSS clamp for the packets that the path carries")
			}
			assert.Positive(t, pspPackets(bind.LanePackets())-psp, "PSP packets after the change")
			// The packets of the TCP connection opened the peer session again, in PSP mode.
			for _, ta := range []*testAgent{a, b} {
				require.Eventually(t, func() bool {
					ta.a.mu.Lock()
					defer ta.a.mu.Unlock()
					for _, p := range ta.a.peers {
						return len(ta.a.peers) == 1 && p != inQUIC && p.bp != nil && !p.quic
					}
					return false
				}, 10*time.Second, 10*time.Millisecond, "one peer session in PSP mode")
			}
			require.Eventually(t, func() bool { return rc.pc.Shards() == 1 }, 5*time.Second, 10*time.Millisecond, "the QUIC shards stay open")
			same("on the peer session of PSP mode")
		})
	}
}

// TestPSPRetryStart checks which sessions probe PSP again: one in QUIC mode from a
// failed probe, on a relay that changes the mode of an open session.
func TestPSPRetryStart(t *testing.T) {
	timeout := dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT
	cases := []struct {
		name    string
		reason  dp.FallbackReason
		version *dp.Version // Version of the relay. Nil is a relay from before revisions.
		want    bool
	}{
		{name: "probe failed", reason: timeout, version: &dp.Version{Revision: modeChange}, want: true},
		{name: "probe failed, later relay", reason: timeout, version: &dp.Version{Revision: modeChange + 1}, want: true},
		{name: "probe failed, relay below the revision", reason: timeout, version: &dp.Version{Revision: modeChange - 1}},
		{name: "probe failed, relay from before revisions", reason: timeout},
		{name: "QUIC mode from the config", reason: dp.FallbackReason_FALLBACK_REASON_CONFIG, version: &dp.Version{Revision: modeChange}},
		{name: "PSP mode", version: &dp.Version{Revision: modeChange}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newPSPRetry(&relayConn{reason: tc.reason, version: tc.version})
			assert.Equal(t, tc.want, r.timer.Stop(), "the timer of the next probe runs")
		})
	}
}
