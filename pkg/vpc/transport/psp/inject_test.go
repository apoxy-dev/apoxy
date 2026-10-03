// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"encoding/binary"
	"hash/maphash"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// recorder is the netstack of a NIC. It keeps the sequence numbers of the
// packets of each source port. When gate is set, it waits on gate.
type recorder struct {
	entered chan struct{}
	gate    chan struct{}

	mu   sync.Mutex
	got  map[uint16][]uint32
	n    int
	last []byte // A copy of the last packet.
}

func newRecorder(t *testing.T) (*recorder, *channel.Endpoint) {
	r := &recorder{entered: make(chan struct{}, 1), got: map[uint16][]uint32{}}
	ep := channel.New(16, DefaultMTU, "")
	ep.Attach(r)
	t.Cleanup(ep.Close)
	return r, ep
}

func (r *recorder) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkb *stack.PacketBuffer) {
	select {
	case r.entered <- struct{}{}:
	default:
	}
	if r.gate != nil {
		<-r.gate
	}
	v := pkb.ToView()
	defer v.Release()
	b := v.AsSlice()
	r.mu.Lock()
	defer r.mu.Unlock()
	port := binary.BigEndian.Uint16(b[20:])
	r.got[port] = append(r.got[port], binary.BigEndian.Uint32(b[28:]))
	r.n++
	r.last = bytes.Clone(b)
}

func (r *recorder) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// flowPacket returns a UDP packet with the source port of the flow and the
// sequence number seq.
func flowPacket(flow uint16, seq uint32) []byte {
	p := packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 17, flow, 2, 64)
	binary.BigEndian.PutUint32(p[28:], seq)
	return p
}

// TestInjectBatch gives packets of many flows to inject workers, and checks
// that the netstack gets the packets of each flow in order.
func TestInjectBatch(t *testing.T) {
	cases := []struct {
		name    string
		workers int
		flows   int
		perFlow int
		read    int // Packets in one read.
		bad     int // Packets that are not IP, at the start.
	}{
		{name: "one worker", workers: 1, flows: 3, perFlow: 50, read: 8, bad: 2},
		{name: "one flow", workers: 4, flows: 1, perFlow: 200, read: 8},
		{name: "many flows", workers: 4, flows: 16, perFlow: 30, read: 8},
		{name: "large read", workers: 2, flows: 1, perFlow: 3 * maxInjectBatch, read: 3 * maxInjectBatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ep := newRecorder(t)
			var b Binding
			done := make(chan struct{})
			defer close(done)
			j := newInjectBatch(ep, &b.stats, maphash.MakeSeed(), tc.workers, done, nil)
			for range tc.bad {
				j.add([]byte{0})
			}
			total := tc.flows * tc.perFlow
			for i := range total {
				pkt := flowPacket(uint16(1+i%tc.flows), uint32(i/tc.flows))
				j.add(pkt)
				// The batch must not keep pkt.
				clear(pkt)
				for _, p := range j.pend {
					require.Less(t, len(p), maxInjectBatch, "a full batch waits for the read end")
				}
				if (i+1)%tc.read == 0 {
					j.flush()
				}
			}
			j.flush()
			require.Eventually(t, func() bool { return b.Stats().RxPackets == uint64(total) },
				5*time.Second, time.Millisecond, "%d of %d packets", r.count(), total)
			assert.Equal(t, Stats{RxPackets: uint64(total), RxDrops: uint64(tc.bad)}, b.Stats())
			r.mu.Lock()
			defer r.mu.Unlock()
			for f := range tc.flows {
				assert.Equal(t, seqs(tc.perFlow), r.got[uint16(1+f)], "flow %d", 1+f)
			}
		})
	}
}

// TestInjectBatchFullQueue checks that the read loop waits while the queue of
// a worker is full, and stops waiting when the driver closes. Then the worker
// drops the batches in its queue.
func TestInjectBatchFullQueue(t *testing.T) {
	cases := []struct {
		name  string
		close bool // The driver closes while the read loop waits.
	}{
		{name: "worker catches up"},
		{name: "driver closes", close: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ep := newRecorder(t)
			gate := make(chan struct{})
			r.gate = gate
			openGate := sync.OnceFunc(func() { close(gate) })
			var b Binding
			done := make(chan struct{})
			closeDone := sync.OnceFunc(func() { close(done) })
			defer closeDone()
			defer openGate()
			j := newInjectBatch(ep, &b.stats, maphash.MakeSeed(), 1, done, nil)

			// The worker takes the first batch and waits in the netstack. The
			// next injectQueue batches fill its queue.
			for i := range 1 + injectQueue {
				j.add(flowPacket(1, uint32(i)))
				j.flush()
				if i == 0 {
					<-r.entered
				}
			}
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				j.add(flowPacket(1, 1+injectQueue))
				j.flush()
			}()
			select {
			case <-sent:
				t.Fatal("The read loop did not wait for the worker.")
			case <-time.After(50 * time.Millisecond):
			}
			if tc.close {
				closeDone()
				<-sent
				assert.Equal(t, Stats{RxDrops: 1}, b.Stats())
				openGate()
				require.Eventually(t, func() bool {
					st := b.Stats()
					return st.RxPackets+st.RxDrops == 2+injectQueue && len(j.in[0]) == 0
				}, 5*time.Second, time.Millisecond, "the worker did not drop its queue: %+v", b.Stats())
				return
			}
			openGate()
			<-sent
			require.Eventually(t, func() bool { return b.Stats().RxPackets == 2+injectQueue }, 5*time.Second, time.Millisecond)
			assert.Equal(t, Stats{RxPackets: 2 + injectQueue}, b.Stats())
			r.mu.Lock()
			defer r.mu.Unlock()
			assert.Equal(t, seqs(2+injectQueue), r.got[1])
		})
	}
}

// seqs returns the sequence numbers 0 to n-1.
func seqs(n int) []uint32 {
	s := make([]uint32, n)
	for i := range s {
		s[i] = uint32(i)
	}
	return s
}
