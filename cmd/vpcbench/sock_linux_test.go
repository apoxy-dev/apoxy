// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSockDrops fills the receive buffer of a socket, and checks that sockDrops counts
// the packets that the socket dropped.
func TestSockDrops(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer rx.Close()
	require.NoError(t, rx.SetReadBuffer(4096))
	assert.Positive(t, sockRcvbuf(rx))
	assert.Zero(t, sockDrops(rx))

	tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer tx.Close()
	pkt := make([]byte, 1000)
	const sent = 200
	for range sent {
		_, err := tx.Write(pkt)
		require.NoError(t, err)
	}
	drops := sockDrops(rx)
	assert.Positive(t, drops, "a 4 KiB buffer holds only some packets")
	assert.Less(t, drops, int64(sent))
}
