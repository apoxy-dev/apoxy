// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

// On Linux, quic-go reads 64 packets in one read; on macOS, one. The failed read needs three.

// failBatchConn is a lane socket whose one read fails after pkts: its last packet has a bad control
// message. With wait, the read waits for the read deadline that Transport.Close sets.
type failBatchConn struct {
	*net.UDPConn
	pkts     [][]byte
	wait     bool
	deadline chan struct{}
	once     sync.Once
	read     bool
}

func (c *failBatchConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		c.once.Do(func() { close(c.deadline) })
	}
	return c.UDPConn.SetReadDeadline(t)
}

func (c *failBatchConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	if c.read {
		return 0, net.ErrClosed
	}
	c.read = true
	if c.wait {
		<-c.deadline
	}
	for i, p := range c.pkts {
		ms[i].N = copy(ms[i].Buffers[0], p)
		ms[i].NN = 0
		ms[i].Addr = c.LocalAddr()
	}
	// A control message header is longer than 4 bytes.
	bad := &ms[len(c.pkts)]
	bad.N, bad.NN, bad.Addr = 1, 4, c.LocalAddr()
	clear(bad.OOB[:4])
	return len(c.pkts) + 1, nil
}

// TestLaneReadFails gives a lane read loop a read that fails after two PSP packets, by itself
// or when the binding closes. The read loop ends the read, and each packet counts once.
func TestLaneReadFails(t *testing.T) {
	for _, k := range rxKinds {
		for _, closes := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/close=%v", k, closes), func(t *testing.T) {
				a, b := newPair(t)
				offer(t, time.Now(), a, b)
				useDriver(t, b, k)
				uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				require.NoError(t, err)
				t.Cleanup(func() { _ = uc.Close() })
				c := &failBatchConn{UDPConn: uc, wait: closes, deadline: make(chan struct{})}
				for i := range 2 {
					c.pkts = append(c.pkts, seal(a, packet(a.v4, b.v4, 17, uint16(1+i), 2, 100))[addrLen:])
				}
				// The read loop of lane 1, as ReadLanes makes it.
				tr := &quic.Transport{
					Conn:                 c,
					NonQUICPacketHandler: func(pkt []byte, _ net.Addr) { b.b.receive(&b.b.lanes[1], pkt) },
					NonQUICBatchEnd:      func() { b.b.readEnd(&b.b.lanes[1]) },
				}
				require.NoError(t, tr.Start())
				t.Cleanup(func() { _ = tr.Close() })
				if closes {
					// Close closes the read loops of the binding.
					b.b.mu.Lock()
					b.b.readers[1] = tr
					b.b.mu.Unlock()
					require.NoError(t, b.b.Close())
				}
				waitCounted(t, b, Stats{}, 2)
				if !closes {
					assert.Equal(t, Stats{RxPackets: 2}, b.b.Stats())
				}
				time.Sleep(10 * time.Millisecond)
				assert.Equal(t, uint64(2), counted(b.b.Stats()), "no packet counts twice")
			})
		}
	}
}
