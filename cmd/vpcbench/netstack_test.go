// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// TestNetstackLinkDrops sends UDP packets on a netstack with no driver, so the
// packets stay in the queue of the channel endpoint until it is full.
func TestNetstackLinkDrops(t *testing.T) {
	cases := []struct {
		name    string
		packets int
		full    bool // The packets fill the queue.
	}{
		{name: "no packets"},
		{name: "queue not full", packets: 100},
		{name: "queue full", packets: 5000, full: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns, err := netstack.NewStack(1280, "", netstack.WithoutIPTables())
			require.NoError(t, err)
			t.Cleanup(ns.Close)
			self := netip.MustParseAddr("10.0.0.1")
			require.NoError(t, ns.AddAddr(netip.PrefixFrom(self, self.BitLen())))
			n := &netstackNet{ns: ns, b: &psp.Binding{}}
			c, err := n.DialUDP(netip.MustParseAddrPort("10.0.0.2:9"))
			require.NoError(t, err)
			defer c.Close()

			for range tc.packets {
				// A write can fail when the stack counts the drop as an error.
				_, _ = c.Write([]byte("x"))
			}
			dropped := tc.packets - ns.Endpoint.NumQueued()
			if tc.full {
				require.Positive(t, dropped, "the queue did not fill")
			} else {
				require.Zero(t, dropped)
			}
			assert.Equal(t, int64(dropped), n.LinkDrops())
		})
	}
}
