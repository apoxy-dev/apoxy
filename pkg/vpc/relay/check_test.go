// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// agentCheck is the agent end of the PSP path check of a test agent.
type agentCheck struct {
	a    agent
	k    p2p.ProbeKeys
	bfd  *p2p.Check
	lose int          // Packets that the path loses after each packet that it carries.
	size int          // Size of the BFD packets of the agent. Zero means no padding.
	got  atomic.Int32 // Size of the last BFD packet of the relay.
}

func (c *agentCheck) send(bfd *p2p.Check) {
	bfd.SetSize(c.size)
	pkt := bfd.Append(nil, p2p.Probe{SID: c.k.SID, Counter: testCounter.Add(1)}, &c.k.Dialer)
	_, _ = c.a.tr.WriteTo(pkt, c.a.to)
}

// run sends a BFD packet each period, and gives the BFD packets of the relay
// to the check, until ctx ends.
func (c *agentCheck) run(ctx context.Context, tx time.Duration) {
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := c.a.tr.ReadNonQUICPacket(ctx, buf)
			if err != nil {
				return
			}
			pr, err := p2p.OpenProbe(buf[:n], &c.k.Listener)
			if err != nil || pr.BFD == nil {
				continue
			}
			c.got.Store(int32(n))
			if c.bfd.Receive(pr) {
				c.send(c.bfd)
			}
		}
	}()
	t := time.NewTicker(tx)
	defer t.Stop()
	for i := 0; ; i++ {
		if i%(c.lose+1) == 0 {
			c.send(c.bfd)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// TestPathCheck checks the relay end of the PSP path check: a session changes
// to QUIC mode with no call of the agent, and a Rekey call changes it back.
func TestPathCheck(t *testing.T) {
	const tx = 200 * time.Millisecond
	old := checkTx
	checkTx = tx
	t.Cleanup(func() { checkTx = old })
	ca := newCA(t)
	h := newHarness(t, ca)
	cases := []struct {
		name string
		lose int  // See agentCheck.
		size int  // See agentCheck.
		stop bool // The BFD packets of the agent stop.
		down bool // The agent sends a BFD packet in the Down state.
		want dp.Mode
	}{
		{name: "each packet comes", want: dp.Mode_MODE_PSP},
		{name: "1 of 2 packets lost", lose: 1, want: dp.Mode_MODE_PSP},
		{name: "padded packets", size: 1412 + 40, want: dp.Mode_MODE_PSP},
		{name: "packets stop", stop: true, want: dp.Mode_MODE_QUIC},
		{name: "agent is Down", down: true, want: dp.Mode_MODE_QUIC},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := h.mustDial(t, ca.agentCert(t, vpcA, fmt.Sprintf("a%d", i)))
			s := h.session(t, a)
			open(t, a)
			c := &agentCheck{a: a, k: probeKeys(t, a), bfd: p2p.NewCheck(p2p.RoleAgent, tx), lose: tc.lose, size: tc.size}
			t.Cleanup(c.bfd.Close)
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			go c.run(ctx, tx)
			up := func() bool {
				h.r.mu.RLock()
				defer h.r.mu.RUnlock()
				return s.check != nil && s.check.bfd.Up()
			}
			require.Eventually(t, func() bool { return up() && c.bfd.Up() }, 5*time.Second, 5*time.Millisecond, "the two ends are not Up")

			if tc.want == dp.Mode_MODE_PSP {
				require.Never(t, func() bool { return modeOf(h.r, s) != dp.Mode_MODE_PSP }, 12*tx, tx/4, "the session left PSP mode")
				assert.True(t, up())
				// The relay pads its packets to the size of the packets of the agent.
				assert.Equal(t, int32(max(tc.size, p2p.MinProbeLen+24)), c.got.Load(), "size of the BFD packets of the relay")
				return
			}
			if tc.stop {
				stop()
			}
			if tc.down {
				// The packets in the Up state come as before.
				first := p2p.NewCheck(p2p.RoleAgent, tx)
				t.Cleanup(first.Close)
				c.send(first)
			}
			require.Eventually(t, func() bool { return modeOf(h.r, s) == dp.Mode_MODE_QUIC }, 5*time.Second, 5*time.Millisecond,
				"the session stays in PSP mode")
			h.r.mu.RLock()
			assert.Nil(t, s.check)
			assert.Nil(t, s.rx)
			assert.Nil(t, s.tx)
			assert.Empty(t, s.relaySAs)
			h.r.mu.RUnlock()
			// The relay told the agent end that it is Down.
			if !tc.stop {
				require.Eventually(t, func() bool { return c.bfd.Lost(time.Now()) }, 5*time.Second, 5*time.Millisecond)
			}

			rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := a.c.Rekey(rctx, keyproto.ToProto(newPSPReceiver(t, time.Now()).req))
			require.NoError(t, err)
			assert.Equal(t, dp.Mode_MODE_PSP, modeOf(h.r, s))
			h.r.mu.RLock()
			defer h.r.mu.RUnlock()
			assert.NotNil(t, s.check)
			assert.NotNil(t, s.rx)
		})
	}
}
