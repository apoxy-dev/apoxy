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

func TestRxQueues(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name   string
		queues int
		want   int
	}{
		{"no device", -1, 1},
		{"no queues", 0, 1},
		{"one queue", 1, 1},
		{"8 queues", 8, 8},
		{"more queues than lanes", 32, keys.MaxLanes},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dev := fmt.Sprintf("eth%d", i)
			if tc.queues >= 0 {
				require.NoError(t, os.MkdirAll(filepath.Join(root, dev, "queues", "tx-0"), 0o755))
			}
			for q := range max(tc.queues, 0) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, dev, "queues", fmt.Sprintf("rx-%d", q)), 0o755))
			}
			assert.Equal(t, tc.want, rxQueues(root, dev))
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
			// A loopback device has one RX queue.
			assert.Equal(t, 1, RxLanes(tc.addr))
		})
	}
}
