// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/atoonk/packetio/afxdp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestSendBuffer gives a copy-mode TX socket room for each TX frame, and a zero-copy socket none:
// zero-copy does not use the send buffer.
func TestSendBuffer(t *testing.T) {
	cases := []struct {
		name      string
		zeroCopy  bool
		frames    int
		frameSize int
		want      int
	}{
		{name: "copy mode", frames: 4096, frameSize: 2048, want: 8 << 20},
		{name: "copy mode, ENA frames", frames: 4096, frameSize: 4096, want: 16 << 20},
		{name: "zero-copy", zeroCopy: true, frames: 4096, frameSize: 4096, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sendBuffer(tc.zeroCopy, tc.frames, tc.frameSize))
		})
	}
}

// TestDeviceSendBuffer opens a veth link, which has only copy mode. Before the first send, each TX
// socket has a send buffer for all its TX frames. The kernel doubles the value for its own use.
func TestDeviceSendBuffer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for veth and AF_XDP")
	}
	const queues = 2
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "rsb0", MTU: 1500, NumTxQueues: queues, NumRxQueues: queues},
		PeerName:  "psb0", PeerNumTxQueues: queues, PeerNumRxQueues: queues,
	}
	require.NoError(t, netlink.LinkAdd(veth))
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	for _, name := range []string{"rsb0", "psb0"} {
		l, err := netlink.LinkByName(name)
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(l))
	}
	l, err := netlink.LinkByName("rsb0")
	require.NoError(t, err)

	own := []netip.Prefix{netip.MustParsePrefix("10.98.0.1/24")}
	d, err := OpenDevice(Interface{Name: "rsb0", MAC: l.Attrs().HardwareAddr, Own: own})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer func() { require.NoError(t, d.Run(ctx)) }()

	require.Equal(t, queues, d.dev.NumTxQueues())
	for i := range queues {
		q := d.dev.TxQueue(i).(*afxdp.TxQueue)
		s := q.Socket()
		zc, err := s.ZeroCopy()
		require.NoError(t, err)
		require.False(t, zc, "veth has no zero-copy")
		frames := q.NumFreeFrames() + q.NumInFlight()
		got, err := unix.GetsockoptInt(s.FD(), unix.SOL_SOCKET, unix.SO_SNDBUF)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, got, 2*frames*s.FrameSize(), "queue %d", i)
	}
}
