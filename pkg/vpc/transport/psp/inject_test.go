// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// recorder is the netstack of a NIC. It keeps the sequence numbers of the
// packets of each source port. When hold is set, it waits on hold.
type recorder struct {
	entered chan struct{}
	hold    chan struct{}

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
	if r.hold != nil {
		<-r.hold
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
			hold := make(chan struct{})
			r.hold = hold
			release := sync.OnceFunc(func() { close(hold) })
			var b Binding
			done := make(chan struct{})
			closeDone := sync.OnceFunc(func() { close(done) })
			defer closeDone()
			defer release()
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
				release()
				require.Eventually(t, func() bool {
					st := b.Stats()
					return st.RxPackets+st.RxDrops == 2+injectQueue && len(j.in[0]) == 0
				}, 5*time.Second, time.Millisecond, "the worker did not drop its queue: %+v", b.Stats())
				return
			}
			release()
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

// tcpOpts is the length of the options in the packets of tcpPacket.
const tcpOpts = 12

// tcpPacket returns a TCP packet with the payload, tcpOpts bytes of options and
// valid checksums.
func tcpPacket(src, dst netip.Addr, sport uint16, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	ipLen := header.IPv4MinimumSize
	if src.Is6() {
		ipLen = header.IPv6MinimumSize
	}
	tcpLen := header.TCPMinimumSize + tcpOpts
	b := make([]byte, ipLen+tcpLen+len(payload))
	srcA, dstA := tcpip.AddrFromSlice(src.AsSlice()), tcpip.AddrFromSlice(dst.AsSlice())
	if src.Is4() {
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(b)),
			ID:          0xfffe,
			TTL:         64,
			Protocol:    uint8(header.TCPProtocolNumber),
			SrcAddr:     srcA,
			DstAddr:     dstA,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	} else {
		header.IPv6(b).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(tcpLen + len(payload)),
			TransportProtocol: header.TCPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           srcA,
			DstAddr:           dstA,
		})
	}
	th := header.TCP(b[ipLen:])
	th.Encode(&header.TCPFields{
		SrcPort:    sport,
		DstPort:    443,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: uint8(tcpLen),
		Flags:      flags,
		WindowSize: 512,
	})
	opts := th[header.TCPMinimumSize:tcpLen]
	header.EncodeTSOption(1, 2, opts[header.EncodeNOP(opts)+header.EncodeNOP(opts[1:]):])
	copy(th.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcA, dstA, uint16(len(th)))
	th.SetChecksum(^th.CalculateChecksum(checksum.Combine(xsum, checksum.Checksum(payload, 0))))
	return b
}

// pattern returns n bytes that differ at each offset.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7 / 3)
	}
	return b
}

// pktRecorder is a netstack that keeps a copy of each packet.
type pktRecorder struct {
	mu        sync.Mutex
	pkts      [][]byte
	validated []bool // The RX checksum flag of each packet.
}

func (r *pktRecorder) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkb *stack.PacketBuffer) {
	v := pkb.ToView()
	defer v.Release()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pkts = append(r.pkts, bytes.Clone(v.AsSlice()))
	r.validated = append(r.validated, pkb.RXChecksumValidated)
}

func (*pktRecorder) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// groSeg is a TCP segment of a flow, or a UDP packet when flow is -1. Its
// payload is the bytes off to off+n of the data of the flow.
type groSeg struct {
	flow, off, n int
	ack          uint32 // Added to the ACK number.
	psh, bad     bool   // bad sets a bad checksum.
}

// TestInjectGRO gives the TCP segments of one read to an inject worker, which
// joins the in-order segments of each flow. The netstack must get the
// segments of each flow in order, with the checksum flag set.
func TestInjectGRO(t *testing.T) {
	const mss = 100
	cases := []struct {
		name string
		in   []groSeg
		want []groSeg // Only flow, off and n.
	}{
		{
			name: "in order",
			in:   []groSeg{{off: 0, n: mss}, {off: 100, n: mss}, {off: 200, n: mss}, {off: 300, n: mss}},
			want: []groSeg{{off: 0, n: 400}},
		},
		{
			name: "last short",
			in:   []groSeg{{off: 0, n: mss}, {off: 100, n: mss}, {off: 200, n: 50}, {off: 250, n: mss}},
			want: []groSeg{{off: 0, n: 250}, {off: 250, n: mss}},
		},
		{
			name: "out of order",
			in:   []groSeg{{off: 0, n: mss}, {off: 200, n: mss}, {off: 100, n: mss}, {off: 300, n: mss}},
			want: []groSeg{{off: 0, n: mss}, {off: 200, n: mss}, {off: 100, n: mss}, {off: 300, n: mss}},
		},
		{
			name: "two flows",
			in:   []groSeg{{off: 0, n: mss}, {flow: 1, off: 0, n: mss}, {off: 100, n: mss}, {flow: 1, off: 100, n: mss}},
			want: []groSeg{{off: 0, n: 200}, {flow: 1, off: 0, n: 200}},
		},
		{
			name: "PSH",
			in:   []groSeg{{off: 0, n: mss}, {off: 100, n: mss, psh: true}, {off: 200, n: mss}},
			want: []groSeg{{off: 0, n: 200}, {off: 200, n: mss}},
		},
		{
			name: "other ACK",
			in:   []groSeg{{off: 0, n: mss}, {off: 100, n: mss, ack: 1}, {off: 200, n: mss, ack: 1}},
			want: []groSeg{{off: 0, n: mss}, {off: 100, n: 200}},
		},
		{
			// PSP open authenticated the packets, so GRO does not check
			// the checksums.
			name: "bad checksum",
			in:   []groSeg{{off: 0, n: mss}, {off: 100, n: mss, bad: true}, {off: 200, n: mss}},
			want: []groSeg{{off: 0, n: 300}},
		},
		{
			name: "UDP",
			in:   []groSeg{{off: 0, n: mss}, {flow: -1}, {off: 100, n: mss}},
			want: []groSeg{{flow: -1}, {off: 0, n: 200}},
		},
		{
			// A joined segment has less than 64 KiB.
			name: "most",
			in: func() []groSeg {
				s := make([]groSeg, 60)
				for i := range s {
					s[i] = groSeg{off: i * 1200, n: 1200}
				}
				return s
			}(),
			want: []groSeg{{off: 0, n: 54 * 1200}, {off: 54 * 1200, n: 6 * 1200}},
		},
	}
	for _, v6 := range []bool{false, true} {
		src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
		if v6 {
			src, dst = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
		}
		for _, tc := range cases {
			t.Run(fmt.Sprintf("v6=%t/%s", v6, tc.name), func(t *testing.T) {
				ipLen := header.IPv4MinimumSize
				if v6 {
					ipLen = header.IPv6MinimumSize
				}
				data := pattern(64 * 1200)
				r := &pktRecorder{}
				ep := channel.New(16, MaxMTU, "")
				ep.Attach(r)
				t.Cleanup(ep.Close)
				var b Binding
				done := make(chan struct{})
				defer close(done)
				j := newInjectBatch(ep, &b.stats, maphash.MakeSeed(), 1, done, nil)
				for _, s := range tc.in {
					if s.flow < 0 {
						j.add(packet(src, dst, 17, 1, 2, 64))
						continue
					}
					flags := header.TCPFlagAck
					if s.psh {
						flags |= header.TCPFlagPsh
					}
					p := tcpPacket(src, dst, uint16(1000+s.flow), uint32(s.off), 7+s.ack, flags, data[s.off:s.off+s.n])
					if s.bad {
						p[ipLen+16] ^= 1
					}
					j.add(p)
				}
				j.flush()
				require.Eventually(t, func() bool { return b.Stats().RxPackets == uint64(len(tc.in)) }, 5*time.Second, time.Millisecond)

				r.mu.Lock()
				defer r.mu.Unlock()
				// The order of the flows can change. The order in a flow must not.
				got := map[int][]groSeg{}
				for i, p := range r.pkts {
					assert.True(t, r.validated[i], "packet %d", i)
					if v6 {
						assert.Equal(t, len(p)-ipLen, int(header.IPv6(p).PayloadLength()))
					} else {
						assert.Equal(t, len(p), int(header.IPv4(p).TotalLength()))
					}
					if (v6 && p[6] == 17) || (!v6 && p[9] == 17) {
						got[-1] = append(got[-1], groSeg{flow: -1})
						continue
					}
					th := header.TCP(p[ipLen:])
					s := groSeg{flow: int(th.SourcePort()) - 1000, off: int(th.SequenceNumber()), n: len(th.Payload())}
					got[s.flow] = append(got[s.flow], s)
					assert.True(t, bytes.Equal(data[s.off:s.off+s.n], th.Payload()), "payload of %+v", s)
				}
				want := map[int][]groSeg{}
				for _, s := range tc.want {
					want[s.flow] = append(want[s.flow], s)
				}
				assert.Equal(t, want, got)
				assert.Equal(t, Stats{RxPackets: uint64(len(tc.in))}, b.Stats())
			})
		}
	}
}

// TestInjectChecksum gives a TCP SYN with a bad checksum to a netstack. On the
// PSP path the netstack does not check the checksum and replies with a
// SYN-ACK. On the QUIC path it drops the SYN.
func TestInjectChecksum(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, psp := range []bool{true, false} {
			t.Run(fmt.Sprintf("v6=%t/psp=%t", v6, psp), func(t *testing.T) {
				src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
				if v6 {
					src, dst = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
				}
				ipLen := header.IPv4MinimumSize
				if v6 {
					ipLen = header.IPv6MinimumSize
				}
				s := stack.New(stack.Options{
					NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
				})
				t.Cleanup(s.Close)
				ep := channel.New(16, DefaultMTU, "")
				require.Nil(t, s.CreateNIC(1, ep))
				pa := tcpip.ProtocolAddress{Protocol: protoOf(dst), AddressWithPrefix: tcpip.AddrFromSlice(dst.AsSlice()).WithPrefix()}
				require.Nil(t, s.AddProtocolAddress(1, pa, stack.AddressProperties{}))
				s.SetRouteTable([]tcpip.Route{
					{Destination: header.IPv4EmptySubnet, NIC: 1},
					{Destination: header.IPv6EmptySubnet, NIC: 1},
				})
				ln, err := gonet.ListenTCP(s, fullAddr(dst, 443), protoOf(dst))
				require.NoError(t, err)
				t.Cleanup(func() { _ = ln.Close() })

				syn := tcpPacket(src, dst, 1000, 1, 0, header.TCPFlagSyn, nil)
				syn[ipLen+16] ^= 1
				if psp {
					var b Binding
					done := make(chan struct{})
					defer close(done)
					j := newInjectBatch(ep, &b.stats, maphash.MakeSeed(), 1, done, nil)
					j.add(syn)
					j.flush()
					require.Eventually(t, func() bool { return ep.NumQueued() > 0 }, 5*time.Second, time.Millisecond)
					pkb := ep.Read()
					defer pkb.DecRef()
					v := pkb.ToView()
					defer v.Release()
					assert.Equal(t, header.TCPFlagSyn|header.TCPFlagAck, header.TCP(v.AsSlice()[ipLen:]).Flags())
					assert.Zero(t, s.Stats().TCP.ChecksumErrors.Value())
				} else {
					require.True(t, inject(ep, syn))
					assert.Equal(t, uint64(1), s.Stats().TCP.ChecksumErrors.Value())
					assert.Zero(t, ep.NumQueued())
				}
			})
		}
	}
}

// BenchmarkInjectGRO gives reads of 64 in-order TCP segments of one flow to
// GRO, with GRO on and off. The netstack has no address and drops them.
func BenchmarkInjectGRO(b *testing.B) {
	for _, v6 := range []bool{false, true} {
		for _, on := range []bool{true, false} {
			b.Run(fmt.Sprintf("v6=%t/gro=%t", v6, on), func(b *testing.B) {
				src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
				if v6 {
					src, dst = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
				}
				const mss = DefaultMTU - 72
				data := pattern(maxInjectBatch * mss)
				pkts := make([][]byte, maxInjectBatch)
				for i := range pkts {
					pkts[i] = tcpPacket(src, dst, 1000, uint32(i*mss), 7, header.TCPFlagAck, data[i*mss:(i+1)*mss])
				}
				ep := nullStack(b)
				g := &gro.GRO{Dispatcher: injector{ep}}
				g.Init(on)
				batch := make([]*stack.PacketBuffer, 0, maxInjectBatch)
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					for _, p := range pkts {
						pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
						pkb.NetworkProtocolNumber = protoOf(src)
						batch = append(batch, pkb)
					}
					for _, pkb := range batch {
						g.Enqueue(pkb)
					}
					g.Flush()
					for i := range batch {
						batch[i].DecRef()
						batch[i] = nil
					}
					batch = batch[:0]
				}
			})
		}
	}
}
