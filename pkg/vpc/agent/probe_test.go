// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPathMTU checks the device MTU and the MSS clamp that the path probes
// set. The agent socket drops packets above a size in each session.
func TestPathMTU(t *testing.T) {
	cases := []struct {
		name      string
		vpcMTU    uint32
		override  int
		drop      []int32 // Largest packet that the agent sends, per session. Zero means no limit.
		wantDev   int
		wantClamp []int // Per session.
	}{
		{"default MTU", 0, 0, []int32{1400}, 1280, []int{0}},
		{"probe passes", 1360, 0, []int32{0}, 1360, []int{0}},
		{"largest MTU", 1412, 0, []int32{0}, 1412, []int{0}},
		{"probe fails", 1372, 0, []int32{1400}, 1280, []int{0}},
		{"override", 1372, 1300, []int32{1400}, 1300, []int{0}},
		{"override above the VPC MTU", 1300, 1372, []int32{0}, 1300, []int{0}},
		{"later probes fail and pass", 1372, 0, []int32{0, 1400, 0}, 1372, []int{0, 1280, 0}},
		{"first probe fails", 1372, 0, []int32{1400, 0}, 1280, []int{0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.mtu = tc.vpcMTU
			r := w.relay(t, "relay-1")
			conn := &lossyConn{}
			conn.max.Store(tc.drop[0])
			ta := w.agent(t, "a", r, agentOptions{mtu: tc.override, conn: conn})
			for i, drop := range tc.drop {
				if i > 0 {
					conn.max.Store(drop)
					ta.reconnect()
				}
				ta.attached(t)
				b := ta.binding()
				assert.Equal(t, tc.wantDev, b.DeviceMTU(), "session %d", i)
				assert.Equal(t, tc.wantClamp[i], b.ClampMTU(), "session %d", i)
			}
		})
	}
}
