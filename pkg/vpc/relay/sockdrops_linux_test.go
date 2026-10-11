// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSocketDrops checks that the relay reads the packets that the kernel drops
// at a socket with a full receive buffer.
func TestSocketDrops(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetReadBuffer(4096))
	n, ok := socketDrops(c)
	require.True(t, ok)
	assert.Zero(t, n)

	// No one reads the socket, so its small buffer takes only the first packets.
	const sent = 200
	out, err := net.DialUDP("udp4", nil, c.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer out.Close()
	pkt := make([]byte, 1200)
	for range sent {
		_, err := out.Write(pkt)
		require.NoError(t, err)
	}
	n, ok = socketDrops(c)
	require.True(t, ok)
	assert.Greater(t, n, uint64(0))
	assert.Less(t, n, uint64(sent))
}
