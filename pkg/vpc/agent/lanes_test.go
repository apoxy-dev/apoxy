// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestLanes checks the lane ports that an agent registers at its relay. The
// relay peer has one SA lane, so the PSP packets go on lane 0, and the relay
// takes the keepalives of the lane ports.
func TestLanes(t *testing.T) {
	cases := []struct {
		name       string
		relayLanes int // Lane port limit of the relay.
		lanes      int // Config.Lanes of the agents.
		want       int // Lane sockets of the agent.
	}{
		{name: "relay takes the lane ports", relayLanes: relay.MaxLaneSources, lanes: 4, want: 3},
		{name: "relay limit below the queues", relayLanes: 2, lanes: 8, want: 2},
		{name: "relay takes no lane ports", lanes: 4},
		{name: "one queue", relayLanes: relay.MaxLaneSources, lanes: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.relayCfg = relay.Config{LaneSources: tc.relayLanes}
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{mode: TransportAuto, lanes: tc.lanes})
			b := w.agent(t, "b", r, agentOptions{mode: TransportAuto, lanes: tc.lanes})
			ea, eb := a.attached(t), b.attached(t)
			require.Eventually(t, func() bool { return a.a.Status().Mode == dp.Mode_MODE_PSP }, 10*time.Second, 10*time.Millisecond,
				"the session commits to PSP mode")
			echo(t, b.stack, eb.addr, 9000)
			for i := range 8 {
				ping(t, a.stack, ea.addr, eb.addr, 9000, fmt.Sprintf("flow %d", i))
			}
			assert.Len(t, a.binding().LaneConns(), tc.want, "lane sockets")
			assert.Len(t, a.binding().LanePackets(), 1, "packets of each lane: %v", a.binding().LanePackets())
			assert.NotZero(t, a.binding().LanePackets()[0])
			assert.Zero(t, relayDrops(t, r)["unknown_source"])
			assert.Zero(t, relayDrops(t, r)["malformed"], "the relay takes the lane keepalives")
		})
	}
}
