// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestPathMTU checks the device MTU, and the MSS clamp that the path probe at the
// change to PSP mode sets. The agent socket drops packets above a size in each session.
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
		{"probe fails", 1372, 0, []int32{1400}, 1372, []int{psp.QUICMTU}},
		{"override", 1372, 1300, []int32{1400}, 1300, []int{0}},
		{"override above the VPC MTU", 1300, 1372, []int32{0}, 1300, []int{0}},
		{"later probes fail and pass", 1372, 0, []int32{0, 1400, 0}, 1372, []int{0, psp.QUICMTU, 0}},
		{"first probe fails", 1372, 0, []int32{1400, 0}, 1372, []int{psp.QUICMTU, 0}},
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

// TestProbeRefusedSession starts an agent whose relay refuses each connection.
// The agent must send at most one path probe for each connection.
func TestProbeRefusedSession(t *testing.T) {
	cases := []struct {
		name   string
		refuse func(t *testing.T, w *world, r *testRelay)
	}{
		{"cert from another CA", func(t *testing.T, w *world, _ *testRelay) { w.trust.SetCA(newCA(t).CA) }},
		{"relay drains", func(_ *testing.T, _ *world, r *testRelay) { r.srv.Drain(context.Background(), nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			tc.refuse(t, w, r)
			conn := &lossyConn{}
			a := w.agent(t, "a", r, agentOptions{conn: conn, quicStart: true})
			// The agent dials again after each refusal, with a new session ID.
			require.Never(t, func() bool {
				return slices.ContainsFunc(conn.probeRuns(), func(r probeRun) bool { return r.n > 1 })
			}, 3*time.Second, 20*time.Millisecond, "path probes of one connection")
			assert.Empty(t, a.attach, "the agent attached")
		})
	}
}

// TestPSPAddr checks where an agent sends the PSP packets of a session.
func TestPSPAddr(t *testing.T) {
	dialed := netip.MustParseAddr("192.0.2.1")
	cases := []struct {
		name string
		host string
		port uint32
		want string // Empty means that the dial fails.
	}{
		{name: "empty host is the dialed host", port: 1000, want: "192.0.2.1:1000"},
		{name: "set host", host: "198.51.100.7", port: 1001, want: "198.51.100.7:1001"},
		{name: "set IPv6 host", host: "2001:db8::7", port: 1001, want: "[2001:db8::7]:1001"},
		{name: "host that is not an IP address", host: "relay.example.net", port: 1000},
		{name: "port 0", host: "198.51.100.7"},
		{name: "port 0 with an empty host"},
		{name: "port above the range", port: 65536},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pspAddr(&dp.Welcome{PspHost: tc.host, PspPort: tc.port}, dialed)
			if tc.want == "" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}
