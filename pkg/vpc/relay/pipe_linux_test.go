// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pipeReceiver is a loopback socket that keeps the sequence numbers of the packets
// that it gets.
type pipeReceiver struct {
	uc   *net.UDPConn
	mu   sync.Mutex
	seqs []uint32
}

func newPipeReceiver(t *testing.T) *pipeReceiver {
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	// The sender is faster than the reader, mostly in race builds.
	require.NoError(t, uc.SetReadBuffer(1<<20))
	r := &pipeReceiver{uc: uc}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, err := uc.Read(buf)
			if err != nil {
				return
			}
			if n >= 4 {
				r.mu.Lock()
				r.seqs = append(r.seqs, binary.BigEndian.Uint32(buf))
				r.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() {
		_ = uc.Close()
		<-done
	})
	return r
}

func (r *pipeReceiver) addr() netip.AddrPort { return r.uc.LocalAddr().(*net.UDPAddr).AddrPort() }

func (r *pipeReceiver) got() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint32(nil), r.seqs...)
}

// newTestPipe returns a pipe on a loopback socket that stops when done closes. It
// does not run the sender.
func newTestPipe(t *testing.T, done <-chan struct{}, drops *atomic.Uint64) *fwdPipe {
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = uc.Close() })
	p := newFwdPipe(&quic.Transport{Conn: uc}, done, drops)
	require.NotNil(t, p)
	return p
}

// pipePacket returns a packet of 40 B with the sequence number seq.
func pipePacket(seq uint32) []byte {
	b := make([]byte, 40)
	binary.BigEndian.PutUint32(b, seq)
	return b
}

// TestFwdPipe gives reads of packets to 3 destinations to the pipe, as the read loop
// does. Each destination must get its packets once and in order, also when one read
// fills more than one set.
func TestFwdPipe(t *testing.T) {
	cases := []struct {
		name string
		read int // Packets in one read.
	}{
		{"small reads", 5},
		{"full sets", maxFwd},
		{"read larger than a set", 3*maxFwd + 5},
	}
	const perDst = 200
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var drops atomic.Uint64
			p := newTestPipe(t, t.Context().Done(), &drops)
			go p.run()
			rcvs := []*pipeReceiver{newPipeReceiver(t), newPipeReceiver(t), newPipeReceiver(t)}
			for i := range len(rcvs) * perDst {
				b := pipePacket(uint32(i / len(rcvs)))
				p.add(b, rcvs[i%len(rcvs)].addr())
				// The pipe must not keep b.
				clear(b)
				if (i+1)%tc.read == 0 {
					p.flush()
				}
			}
			p.flush()
			want := make([]uint32, perDst)
			for i := range want {
				want[i] = uint32(i)
			}
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				got := []int{len(rcvs[0].got()), len(rcvs[1].got()), len(rcvs[2].got())}
				assert.Equal(c, []int{perDst, perDst, perDst}, got, "packets of each destination, drops %d", drops.Load())
			}, 5*time.Second, time.Millisecond)
			for i, r := range rcvs {
				assert.Equal(t, want, r.got(), "destination %d", i)
			}
			assert.Zero(t, drops.Load())
		})
	}
}

// TestFwdPipeFull fills all sets while the sender does not run. The read loop must
// wait and drop nothing. When the pipe stops, the read loop stops waiting, and the
// packets in the pipe drop.
func TestFwdPipeFull(t *testing.T) {
	cases := []struct {
		name string
		stop bool // The pipe stops while the read loop waits.
	}{
		{name: "sender catches up"},
		{name: "pipe stops", stop: true},
	}
	// More reads of one packet than the pipe has sets.
	const total = 5 * fwdSets
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var drops atomic.Uint64
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p := newTestPipe(t, ctx.Done(), &drops)
			rcv := newPipeReceiver(t)

			var reads atomic.Int64
			var halt atomic.Bool
			loop := make(chan struct{})
			go func() {
				defer close(loop)
				for i := range total {
					if halt.Load() {
						return
					}
					p.add(pipePacket(uint32(i)), rcv.addr())
					p.flush()
					reads.Add(1)
				}
			}()
			// The loop gives all sets to the sender, then waits for a free set.
			require.Eventually(t, func() bool { return len(p.full) == fwdSets }, 5*time.Second, time.Millisecond)
			select {
			case <-loop:
				t.Fatal("The read loop did not wait for the sender.")
			case <-time.After(50 * time.Millisecond):
			}
			assert.Equal(t, int64(fwdSets), reads.Load())

			if !tc.stop {
				go p.run()
				<-loop
				want := make([]uint32, total)
				for i := range want {
					want[i] = uint32(i)
				}
				require.EventuallyWithT(t, func(c *assert.CollectT) { assert.Len(c, rcv.got(), total) },
					5*time.Second, time.Millisecond)
				assert.Equal(t, want, rcv.got())
				assert.Zero(t, drops.Load())
				return
			}
			halt.Store(true)
			cancel()
			select {
			case <-loop:
			case <-time.After(5 * time.Second):
				t.Fatal("The read loop waits for a stopped pipe.")
			}
			// The packet that waited for a set drops in the loop, and the sender drops the sets.
			sent := uint64(reads.Load())
			assert.Equal(t, uint64(fwdSets+1), sent)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				p.run()
			}()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("The sender did not stop.")
			}
			assert.Empty(t, p.full)
			assert.Equal(t, sent, drops.Load())
			assert.Empty(t, rcv.got())
		})
	}
}
