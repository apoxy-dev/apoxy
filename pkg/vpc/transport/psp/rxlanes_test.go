// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueues(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name     string
		rx, tx   int
		wantRx   int
		wantTx   int
		noDevice bool
	}{
		{name: "no device", noDevice: true, wantRx: 1, wantTx: 1},
		{name: "no queues", wantRx: 1, wantTx: 1},
		{name: "one queue", rx: 1, tx: 1, wantRx: 1, wantTx: 1},
		{name: "8 queues", rx: 8, tx: 8, wantRx: 8, wantTx: 8},
		{name: "more RX than TX queues", rx: 8, tx: 2, wantRx: 8, wantTx: 2},
		{name: "more queues than lanes", rx: 32, tx: 32, wantRx: keys.MaxLanes, wantTx: keys.MaxLanes},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dev := fmt.Sprintf("eth%d", i)
			if !tc.noDevice {
				require.NoError(t, os.MkdirAll(filepath.Join(root, dev, "queues"), 0o755))
			}
			for kind, n := range map[string]int{"rx": tc.rx, "tx": tc.tx} {
				for q := range n {
					require.NoError(t, os.MkdirAll(filepath.Join(root, dev, "queues", fmt.Sprintf("%s-%d", kind, q)), 0o755))
				}
			}
			assert.Equal(t, tc.wantRx, queues(root, dev, "rx"))
			assert.Equal(t, tc.wantTx, queues(root, dev, "tx"))
		})
	}
}

func TestRxLanes(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
		link bool
	}{
		{"loopback", netip.MustParseAddr("127.0.0.1"), true},
		{"invalid address", netip.Addr{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.link, linkTo(tc.addr) != "")
			// A loopback device has one RX and one TX queue.
			assert.Equal(t, 1, RxLanes(tc.addr))
			assert.Equal(t, 1, TxLanes(tc.addr))
		})
	}
}
