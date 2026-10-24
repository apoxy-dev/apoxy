// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestZeroSumReceive sends a PSP packet with UDP checksum 0 to the agent socket and to a lane
// socket, on IPv4 and IPv6. The binding opens it, as the PSP specification requires.
func TestZeroSumReceive(t *testing.T) {
	cases := []struct {
		name    string
		network string
		lane    bool // Send to the socket of lane 1, not to the agent socket.
	}{
		{name: "IPv4 agent socket", network: "udp4"},
		{name: "IPv4 lane socket", network: "udp4", lane: true},
		{name: "IPv6 agent socket", network: "udp6"},
		{name: "IPv6 lane socket", network: "udp6", lane: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPairOn(t, tc.network, 0, 1)
			offer(t, time.Now(), a, b)
			_, sink := useDriver(t, b, pipeKind)
			to := addrOf(b.tr)
			if tc.lane {
				ports := b.b.OpenLanes(2)
				require.Len(t, ports, 1)
				require.NoError(t, b.b.ReadLanes())
				to = netip.AddrPortFrom(to.Addr(), ports[0])
			}
			inner := packet(a.v4, b.v4, 17, 1, 2, 100)
			pkt := seal(a, inner)
			require.NotNil(t, pkt)
			before := b.b.Stats()
			sendZeroSum(t, tc.network, to, pkt[addrLen:])
			waitCounted(t, b, before, 1)
			assert.Equal(t, before.RxPackets+1, b.b.Stats().RxPackets)
			require.Eventually(t, func() bool { return len(sink.packets()) == 1 }, 5*time.Second, time.Millisecond)
			assert.Equal(t, inner, sink.packets()[0])
		})
	}
}

// sendZeroSum sends pkt to dst from a loopback socket of network that sends UDP checksum 0. On
// IPv6 it checks that a socket with no UDP_NO_CHECK6_RX drops the packet, so the checksum is 0.
func sendZeroSum(t *testing.T, network string, dst netip.AddrPort, pkt []byte) {
	t.Helper()
	opt := [2]int{unix.SOL_SOCKET, unix.SO_NO_CHECK}
	if network == "udp6" {
		opt = [2]int{unix.SOL_UDP, unix.UDP_NO_CHECK6_TX}
	}
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: dst.Addr().AsSlice()})
	require.NoError(t, err)
	defer c.Close()
	rc, err := c.SyscallConn()
	require.NoError(t, err)
	var serr error
	require.NoError(t, rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), opt[0], opt[1], 1) }))
	require.NoError(t, serr)
	if network == "udp6" {
		plain, err := net.ListenUDP(network, &net.UDPAddr{IP: dst.Addr().AsSlice()})
		require.NoError(t, err)
		defer plain.Close()
		_, err = c.WriteToUDPAddrPort(pkt, plain.LocalAddr().(*net.UDPAddr).AddrPort())
		require.NoError(t, err)
		require.NoError(t, plain.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		_, _, err = plain.ReadFromUDPAddrPort(make([]byte, 2048))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded, "a socket with no UDP_NO_CHECK6_RX got the packet")
	}
	_, err = c.WriteToUDPAddrPort(pkt, dst)
	require.NoError(t, err)
}
