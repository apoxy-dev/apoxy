// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pipeReceiver is a loopback socket that keeps the sequence numbers of the packets
// that it gets, and the source of the last one.
type pipeReceiver struct {
	uc   *net.UDPConn
	mu   sync.Mutex
	seqs []uint32
	from netip.AddrPort
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
			n, from, err := uc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n >= 4 {
				r.mu.Lock()
				r.seqs = append(r.seqs, binary.BigEndian.Uint32(buf))
				r.from = from
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

func (r *pipeReceiver) source() netip.AddrPort {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.from
}

// pipeCounters are the counters of a test pipe.
type pipeCounters struct {
	closed, queue atomic.Uint64
	sends         sendStats
}

// newTestPipe returns a pipe with n senders on a loopback socket that stops when
// done closes. It does not run the senders.
func newTestPipe(tb testing.TB, n int, done <-chan struct{}) (*fwdPipe, *pipeCounters) {
	tb.Helper()
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = uc.Close() })
	c := &pipeCounters{}
	p := newFwdPipe(&quic.Transport{Conn: uc}, n, done, fwdCounters{closed: &c.closed, queue: &c.queue, sends: &c.sends})
	require.NotNil(tb, p)
	return p, c
}

// waitInUse waits until each sender of p has at most n sets that are not free. A
// test read loop calls it between reads, so that it is not faster than the senders.
func waitInUse(tb testing.TB, p *fwdPipe, n int) {
	tb.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ok := true
		for _, sd := range p.senders {
			sd.mu.Lock()
			ok = ok && sd.made-len(sd.free) <= n
			sd.mu.Unlock()
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			tb.Fatal("The senders did not free their sets.")
		}
		runtime.Gosched()
	}
}

// pipePacket returns a packet of 40 B with the sequence number seq.
func pipePacket(seq uint32) []byte {
	b := make([]byte, 40)
	binary.BigEndian.PutUint32(b, seq)
	return b
}

// seqs returns the sequence numbers 0 to n-1.
func seqs(n int) []uint32 {
	s := make([]uint32, n)
	for i := range s {
		s[i] = uint32(i)
	}
	return s
}

// TestFwdPipe gives reads of packets to 8 destinations to the pipe, as the read loop
// does. Each destination must get its packets once and in order, with one sender
// and with more, also when one read fills more than one set.
func TestFwdPipe(t *testing.T) {
	cases := []struct {
		name    string
		senders int
		read    int // Packets in one read.
	}{
		{"one sender, small reads", 1, 5},
		{"one sender, full sets", 1, maxFwd},
		{"one sender, read larger than a set", 1, 3*maxFwd + 5},
		{"two senders, small reads", 2, 5},
		{"two senders, read larger than a set", 2, 3*maxFwd + 5},
		{"four senders, small reads", 4, 5},
		{"four senders, full sets", 4, maxFwd},
		{"four senders, read larger than a set", 4, 3*maxFwd + 5},
		{"four senders, read larger than a send", 4, 6*maxSend + 5},
	}
	const dsts, perDst = 8, 250
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, c := newTestPipe(t, tc.senders, t.Context().Done())
			p.start()
			rcvs := make([]*pipeReceiver, dsts)
			used := map[*fwdSender]bool{}
			for i := range rcvs {
				rcvs[i] = newPipeReceiver(t)
				used[p.senderOf(rcvs[i].addr())] = true
			}
			assert.Len(t, used, tc.senders, "senders in use")
			for i := range dsts * perDst {
				b := pipePacket(uint32(i / dsts))
				p.add(b, rcvs[i%dsts].addr())
				// The pipe must not keep b.
				clear(b)
				if (i+1)%tc.read == 0 {
					p.flush()
					// One read gives a sender at most tc.read packets.
					waitInUse(t, p, fwdSets-tc.read/maxFwd-2)
				}
			}
			p.flush()
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				for i, r := range rcvs {
					assert.Len(ct, r.got(), perDst, "destination %d, queue drops %d", i, c.queue.Load())
				}
				// A sender counts a send after the socket takes it.
				assert.Equal(ct, uint64(dsts*perDst), c.sends.packets.Load())
			}, 5*time.Second, time.Millisecond)
			for i, r := range rcvs {
				assert.Equal(t, seqs(perDst), r.got(), "destination %d", i)
			}
			assert.Zero(t, c.closed.Load())
			assert.Zero(t, c.queue.Load())
		})
	}
}

// TestFwdPipeSender checks the sender of each destination. The lane ports of one
// receiver get different senders while there are senders left. A destination keeps
// its sender.
func TestFwdPipeSender(t *testing.T) {
	cases := []struct {
		name    string
		senders int
		dsts    []string
		want    []int // The sender of each destination.
	}{
		{"one sender", 1, []string{"192.0.2.1:4000", "192.0.2.1:4001"}, []int{0, 0}},
		{"two lane ports", 2, []string{"192.0.2.1:4000", "192.0.2.1:4001"}, []int{0, 1}},
		{"four lane ports", 4, []string{"192.0.2.1:4000", "192.0.2.1:4001", "192.0.2.1:4002", "192.0.2.1:4003"}, []int{0, 1, 2, 3}},
		{"more destinations than senders", 2, []string{"192.0.2.1:4000", "192.0.2.1:4001", "192.0.2.2:4000", "[2001:db8::1]:4000"}, []int{0, 1, 0, 1}},
		{"a destination comes again", 4, []string{"192.0.2.1:4000", "192.0.2.1:4001", "192.0.2.1:4000", "192.0.2.1:4002"}, []int{0, 1, 0, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newTestPipe(t, tc.senders, t.Context().Done())
			// The second turn shows that each destination keeps its sender.
			for turn := range 2 {
				got := make([]int, len(tc.dsts))
				for i, d := range tc.dsts {
					got[i] = slices.Index(p.senders, p.senderOf(netip.MustParseAddrPort(d)))
				}
				assert.Equal(t, tc.want, got, "turn %d", turn)
			}
		})
	}
}

// TestFwdPipeSets checks that a sender makes a set only when it has no free set,
// so a sender with no packets has no sets.
func TestFwdPipeSets(t *testing.T) {
	const reads = 50
	p, c := newTestPipe(t, 2, t.Context().Done())
	p.start()
	rcv := newPipeReceiver(t)
	busy := p.senderOf(rcv.addr())
	for i := range reads {
		p.add(pipePacket(uint32(i)), rcv.addr())
		p.flush()
		// The sender frees the set before the next read.
		waitInUse(t, p, 0)
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) { assert.Len(ct, rcv.got(), reads) },
		5*time.Second, time.Millisecond)
	assert.Equal(t, seqs(reads), rcv.got())
	for i, sd := range p.senders {
		assert.Equal(t, map[bool]int{true: 1}[sd == busy], sd.made, "sender %d", i)
	}
	assert.Zero(t, c.queue.Load())
}

// TestFwdPipeSource checks that a packet from each sender has the address of the
// transport socket as its source.
func TestFwdPipeSource(t *testing.T) {
	const senders = 4
	p, c := newTestPipe(t, senders, t.Context().Done())
	p.start()
	local := p.tr.Conn.LocalAddr().(*net.UDPAddr).AddrPort()
	// Two destinations can use one hash slot, so add destinations until each sender
	// has one.
	var rcvs []*pipeReceiver
	used := map[*fwdSender]bool{}
	for len(used) < senders {
		r := newPipeReceiver(t)
		rcvs = append(rcvs, r)
		used[p.senderOf(r.addr())] = true
		p.add(pipePacket(0), r.addr())
	}
	p.flush()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for i, r := range rcvs {
			assert.Equal(ct, local, r.source(), "destination %d", i)
		}
	}, 5*time.Second, time.Millisecond)
	assert.Zero(t, c.queue.Load())
}

// TestFwdPipeFull gives one sender more reads than it has sets while no sender
// runs. The read loop must not wait: the packets that the sender cannot take drop,
// and the packets to the other sender do not. When the pipe stops, the packets in
// the pipe drop.
func TestFwdPipeFull(t *testing.T) {
	cases := []struct {
		name string
		stop bool // The pipe stops before the senders run.
	}{
		{name: "senders catch up"},
		{name: "pipe stops", stop: true},
	}
	// The slow sender cannot take extra of its reads. The other sender gets others reads.
	const extra, others = 40, 10
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p, c := newTestPipe(t, 2, ctx.Done())
			slow, other := newPipeReceiver(t), newPipeReceiver(t)
			for p.senderOf(other.addr()) == p.senderOf(slow.addr()) {
				other = newPipeReceiver(t)
			}

			loop := make(chan struct{})
			go func() {
				defer close(loop)
				for i := range fwdSets + extra {
					p.add(pipePacket(uint32(i)), slow.addr())
					p.flush()
				}
				for i := range others {
					p.add(pipePacket(uint32(i)), other.addr())
					p.flush()
				}
			}()
			select {
			case <-loop:
			case <-time.After(5 * time.Second):
				t.Fatal("The read loop waits for a sender.")
			}
			assert.Equal(t, uint64(extra), c.queue.Load())
			assert.Zero(t, c.closed.Load())

			if !tc.stop {
				p.start()
				// The sender frees its sets, so it takes a packet again.
				waitInUse(t, p, 0)
				p.add(pipePacket(fwdSets), slow.addr())
				p.flush()
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					assert.Len(ct, slow.got(), fwdSets+1)
					assert.Len(ct, other.got(), others)
				}, 5*time.Second, time.Millisecond)
				assert.Equal(t, seqs(fwdSets+1), slow.got())
				assert.Equal(t, seqs(others), other.got())
				assert.Equal(t, uint64(extra), c.queue.Load())
				assert.Zero(t, c.closed.Load())
				return
			}
			cancel()
			// The slow sender has no free set. The other sender takes the packet, and
			// then its sets drop.
			p.add(pipePacket(0), slow.addr())
			p.add(pipePacket(0), other.addr())
			p.flush()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				for _, sd := range p.senders {
					p.run(sd)
				}
			}()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("The senders did not stop.")
			}
			for i, sd := range p.senders {
				assert.Empty(t, sd.full, "sender %d", i)
			}
			assert.Equal(t, uint64(fwdSets+others+2), c.closed.Load())
			assert.Equal(t, uint64(extra), c.queue.Load())
			assert.Empty(t, slow.got())
			assert.Empty(t, other.got())
		})
	}
}

// benchInUse is the most sets of a sender that a benchmark keeps in use. It is the
// number of sets of the pipe with one sender that came before.
const benchInUse = 8

// BenchmarkFwdPipe measures the read loop and the senders together. The reads have
// maxFwd packets of 1200 B to loopback sockets that nothing reads. The loop keeps
// at most benchInUse sets of a sender in use, so no packet drops in the pipe.
func BenchmarkFwdPipe(b *testing.B) {
	cases := []struct{ senders, dsts int }{{1, 1}, {1, 4}, {1, 16}, {2, 4}, {4, 4}, {4, 16}}
	for _, tc := range cases {
		b.Run(fmt.Sprintf("senders=%d/dsts=%d", tc.senders, tc.dsts), func(b *testing.B) {
			p, c := newTestPipe(b, tc.senders, b.Context().Done())
			p.start()
			dsts := make([]netip.AddrPort, tc.dsts)
			for i := range dsts {
				uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				require.NoError(b, err)
				b.Cleanup(func() { _ = uc.Close() })
				dsts[i] = uc.LocalAddr().(*net.UDPAddr).AddrPort()
			}
			pkt := make([]byte, 1200)
			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				p.add(pkt, dsts[i%len(dsts)])
				if i++; i%maxFwd == 0 {
					p.flush()
					waitInUse(b, p, benchInUse)
				}
			}
			p.flush()
			waitInUse(b, p, 0)
			b.StopTimer()
			require.Zero(b, c.queue.Load())
			b.ReportMetric(float64(c.sends.packets.Load())/float64(c.sends.messages.Load()), "pkts/msg")
		})
	}
}

// BenchmarkFwdPipeAdd measures the read loop alone: add and flush for reads of
// maxFwd packets of 1200 B. A goroutine frees the sets and sends nothing.
func BenchmarkFwdPipeAdd(b *testing.B) {
	for _, senders := range []int{1, 4} {
		b.Run(fmt.Sprintf("senders=%d", senders), func(b *testing.B) {
			p, c := newTestPipe(b, senders, b.Context().Done())
			for _, sd := range p.senders {
				go func() {
					for {
						select {
						case s := <-sd.full:
							sd.put([]*fwdSet{s})
						case <-p.done:
							return
						}
					}
				}()
			}
			dsts := make([]netip.AddrPort, 4)
			for i := range dsts {
				dsts[i] = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(4000+i))
			}
			pkt := make([]byte, 1200)
			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				p.add(pkt, dsts[i%len(dsts)])
				if i++; i%maxFwd == 0 {
					p.flush()
					waitInUse(b, p, benchInUse)
				}
			}
			b.StopTimer()
			require.Zero(b, c.queue.Load())
		})
	}
}
