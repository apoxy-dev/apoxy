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
	q, _ := sockMem(rx)
	assert.Zero(t, q)

	tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer tx.Close()
	pkt := make([]byte, 1000)
	const sent = 200
	for range sent {
		_, err := tx.Write(pkt)
		require.NoError(t, err)
	}
	q, _ = sockMem(rx)
	assert.Positive(t, q, "the receive queue holds packets")
	drops := sockDrops(rx)
	assert.Positive(t, drops, "a 4 KiB buffer holds only some packets")
	assert.Less(t, drops, int64(sent))
}

// TestSockQueues checks the sum of one queue sample. The send queue of the lane
// send sockets is in the send sum, and not in the receive sum.
func TestSockQueues(t *testing.T) {
	cases := []struct {
		name  string
		lanes int // Lane sockets, each with one packet in its receive queue.
		sent  int // The send queue of the lane send sockets.
	}{
		{name: "agent socket only"},
		{name: "lanes that send on their lane sockets", lanes: 2},
		{name: "lanes with send sockets", lanes: 2, sent: 9000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listen := func() *net.UDPConn {
				c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				return c
			}
			agent := listen()
			var lanes []*net.UDPConn
			var wantRx int64
			for range tc.lanes {
				lc := listen()
				_, err := agent.WriteToUDP(make([]byte, 1000), lc.LocalAddr().(*net.UDPAddr))
				require.NoError(t, err)
				q, _ := sockMem(lc)
				require.Positive(t, q, "the receive queue of a lane socket")
				wantRx += q
				lanes = append(lanes, lc)
			}
			rx, tx := sockQueues(agent, lanes, tc.sent)
			assert.Equal(t, wantRx, rx)
			// A packet on loopback is complete when the send returns.
			assert.Equal(t, int64(tc.sent), tx)
		})
	}
}
