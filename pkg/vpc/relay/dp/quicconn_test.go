// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"context"
	"math/bits"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atoonk/packetio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
)

// fakeDev is a packetio.Device on fake TX queues. Its one RX queue is never read.
type fakeDev struct{ tx []*fakeTx }

func (d fakeDev) Capabilities() packetio.Capabilities { return packetio.Capabilities{} }
func (d fakeDev) NumTxQueues() int                    { return len(d.tx) }
func (d fakeDev) NumRxQueues() int                    { return 1 }
func (d fakeDev) TxQueue(i int) packetio.TxQueue      { return d.tx[i] }
func (d fakeDev) RxQueue(int) packetio.RxQueue        { return nil }
func (d fakeDev) Close() error                        { return nil }

var (
	fakeOwn     = netip.MustParsePrefix("10.99.0.1/24")
	fakePeer    = netip.MustParseAddrPort("10.99.0.2:4433")
	fakePeerMAC = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	// fakeOffLink is not in the own subnet, and the device has no gateway: it has no next hop.
	fakeOffLink = netip.MustParseAddrPort("192.0.2.9:4433")
)

// newFakeDevice opens a device on the TX queue f. fakePeer has a static MAC, so a send to it sends
// no ARP.
func newFakeDevice(t *testing.T, f *fakeTx) *Device {
	t.Helper()
	ifc := Interface{Name: "fake0", MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, Own: []netip.Prefix{fakeOwn}, Mode: configv1alpha1.RelayInterfaceModeDedicated}
	d, err := newDevice(ifc, fakeDev{tx: []*fakeTx{f}}, []txPort{f.port()}, 1500, emptyImpair{}, goAEAD{}, nil)
	require.NoError(t, err)
	t.Cleanup(d.ns.close)
	addr := tcpip.AddrFromSlice(fakePeer.Addr().AsSlice())
	require.Nil(t, d.ns.s.AddStaticNeighbor(nicID, ipv4.ProtocolNumber, addr, fakePeerMAC))
	return d
}

// emptyImpair is an impair map with no entries, for a device on fake queues.
type emptyImpair struct{}

func (emptyImpair) Show() ([]Impairment, error) { return nil, nil }
func (emptyImpair) Close() error                { return nil }

// onRing returns the frames on the TX ring of f, oldest first.
func (f *fakeTx) onRing() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for _, d := range f.txr {
		out = append(out, bytes.Clone(f.mem[d.Addr:d.Addr+uint64(d.Len)]))
	}
	return out
}

// numSends returns the publish calls of f.
func (f *fakeTx) numSends() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sends
}

// checkFrame checks that frame is a UDP datagram from the QUIC port to fakePeer, with DF and the
// ECN bits ecn, and returns its payload.
func checkFrame(t *testing.T, frame []byte, ecn uint8) []byte {
	t.Helper()
	eth := header.Ethernet(frame)
	assert.Equal(t, fakePeerMAC, eth.DestinationAddress())
	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	assert.Equal(t, fakeOwn.Addr(), netip.AddrFrom4(ip.SourceAddress().As4()))
	assert.Equal(t, fakePeer.Addr(), netip.AddrFrom4(ip.DestinationAddress().As4()))
	tos, _ := ip.TOS()
	assert.Equal(t, ecn, tos&0b11, "ECN bits")
	assert.NotZero(t, ip.Flags()&header.IPv4FlagDontFragment, "DF")
	udp := header.UDP(ip.Payload())
	assert.Equal(t, uint16(portQUIC), udp.SourcePort())
	assert.Equal(t, fakePeer.Port(), udp.DestinationPort())
	return udp.Payload()
}

// counted returns the packets of the drop counter of reason.
func counted(d *Device, reason uint8) int {
	return int(d.p.drops[reason].packets.Load())
}

// TestQUICConnWrite checks that a GSO write sends its datagrams in order with one send per rxBatch,
// also after an impair delay, and that each datagram is on the ring or a drop.
func TestQUICConnWrite(t *testing.T) {
	const frames = 256
	five := []int{8, 8, 8, 8, 3}
	cases := []struct {
		name      string
		size      int // len(b).
		gso       int // The GSO segment size, 0 for WriteToECN.
		ring      int // The room on the TX ring.
		offLink   bool
		delay     time.Duration // The impair delay of the peer.
		datagrams int
		sends     int   // The publish calls.
		onRing    []int // The payload size of each frame on the ring.
		from      int   // The offset in b of the first payload on the ring.
		drops     map[uint8]int
	}{
		{name: "one datagram", size: 20, ring: 128, datagrams: 1, sends: 1, onRing: []int{20}},
		{name: "a GSO write of one datagram", size: 8, gso: 8, ring: 128, datagrams: 1, sends: 1, onRing: []int{8}},
		{name: "a GSO write of five datagrams is one send", size: 35, gso: 8, ring: 128, datagrams: 5, sends: 1, onRing: five},
		{name: "a GSO write of a batch and more", size: (rxBatch + 6) * 2, gso: 2, ring: 128, datagrams: rxBatch + 6,
			sends: 2, onRing: slices.Repeat([]int{2}, rxBatch+6)},
		{name: "room for three of five datagrams", size: 35, gso: 8, ring: 3, datagrams: 5, sends: 1, onRing: five[:3],
			drops: map[uint8]int{ReasonTXFull: 2}},
		{name: "a full ring", size: 35, gso: 8, ring: 0, datagrams: 5, sends: 1, drops: map[uint8]int{ReasonTXFull: 5}},
		{name: "no next hop", size: 35, gso: 8, ring: 128, offLink: true, datagrams: 5, drops: map[uint8]int{ReasonNoNeighbor: 5}},
		// A frame of the fake has 64 bytes: 42 for the headers and at most 22 for the payload.
		{name: "datagrams larger than a frame", size: 70, gso: 30, ring: 128, datagrams: 3, sends: 1, onRing: []int{10}, from: 60,
			drops: map[uint8]int{ReasonMTU: 2}},
		{name: "a delayed GSO write is one send", size: 35, gso: 8, ring: 128, delay: 20 * time.Millisecond, datagrams: 5,
			sends: 1, onRing: five},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTx(frames, tc.ring)
			d := newFakeDevice(t, f)
			if tc.delay > 0 {
				dt := newDelayTable([]Impairment{{Port: portQUIC, Peer: netip.PrefixFrom(fakePeer.Addr(), 32), Delay: tc.delay}})
				d.delays.Store(&dt)
			}
			b := make([]byte, tc.size)
			for i := range b {
				b[i] = byte(i)
			}
			orig := bytes.Clone(b)
			const ecn = 0b10
			conn := d.PacketConn().(*quicConn)
			to := net.UDPAddrFromAddrPort(fakePeer)
			if tc.offLink {
				to = net.UDPAddrFromAddrPort(fakeOffLink)
			}
			var n int
			var err error
			if tc.gso == 0 {
				n, err = conn.WriteToECN(b, to, ecn)
			} else {
				n, err = conn.WriteToGSO(b, to, uint16(tc.gso), ecn)
			}
			require.NoError(t, err)
			assert.Equal(t, len(b), n, "a write takes all of b, also the datagrams that drop")
			// quic-go uses the buffer again after the write.
			for i := range b {
				b[i] = 0xff
			}
			if tc.delay > 0 {
				require.Eventually(t, func() bool { return len(f.onRing()) == len(tc.onRing) }, 2*time.Second, time.Millisecond)
			}
			assert.Equal(t, tc.sends, f.numSends(), "publish calls")

			got := f.onRing()
			require.Len(t, got, len(tc.onRing))
			payloads := []byte{}
			for i, frame := range got {
				p := checkFrame(t, frame, ecn)
				assert.Len(t, p, tc.onRing[i], "frame %d", i)
				payloads = append(payloads, p...)
			}
			total := 0
			for _, l := range tc.onRing {
				total += l
			}
			assert.Equal(t, orig[tc.from:tc.from+total], payloads, "the payloads are the datagrams of b, in order")
			drops := 0
			for _, r := range []uint8{ReasonTXFull, ReasonNoNeighbor, ReasonMTU} {
				assert.Equal(t, tc.drops[r], counted(d, r), "drops of reason %d", r)
				drops += counted(d, r)
			}
			assert.Equal(t, tc.datagrams, len(got)+drops, "each datagram is on the ring or a drop")
			assert.Equal(t, frames, f.frames(), "no frame is lost")
		})
	}
}

// TestQUICConnWriters runs GSO writers and receive loops on one TX queue with its kicker. Each
// datagram is sent or tx_full, and no frame is lost.
func TestQUICConnWriters(t *testing.T) {
	const frames, ring, writers, loops, writes = 256, 128, 4, 2, 300
	f := newFakeTx(frames, ring)
	f.hold = true
	d := newFakeDevice(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	kicked := make(chan error, 1)
	go func() { kicked <- d.tx[0].kicker(ctx) }()
	// The kernel completes the frames that it sent a short time after the kick.
	kernel := make(chan struct{})
	go func() {
		defer close(kernel)
		for ctx.Err() == nil {
			f.finish()
			time.Sleep(50 * time.Microsecond)
		}
	}()

	const seg = 6
	conn := d.PacketConn().(*quicConn)
	to := net.UDPAddrFromAddrPort(fakePeer)
	var datagrams, loopSent, loopFull atomic.Int64
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range writes {
				k := 1 + (w+i)%14
				b := bytes.Repeat([]byte{byte(k)}, k*seg)
				n, err := conn.WriteToGSO(b, to, seg, 0b01)
				assert.NoError(t, err)
				assert.Equal(t, len(b), n)
				datagrams.Add(int64(k))
			}
		})
	}
	for range loops {
		wg.Go(func() {
			for range writes {
				s, fl := d.tx[0].send(rxBatch, numbered(0))
				loopSent.Add(int64(s))
				loopFull.Add(int64(bits.OnesCount64(fl)))
			}
		})
	}
	wg.Wait()
	require.Eventually(t, func() bool { return f.pending() == 0 }, 2*time.Second, time.Millisecond)
	cancel()
	<-kernel
	require.NoError(t, <-kicked)
	f.finish()

	quicSent := 0
	for _, frame := range f.sent() {
		if len(frame) == 8 {
			continue // A frame of a receive loop.
		}
		p := checkFrame(t, frame, 0b01)
		assert.Len(t, p, seg)
		quicSent++
	}
	assert.Equal(t, int(loopSent.Load())+quicSent, len(f.sent()), "the kernel sent each published frame one time")
	assert.Equal(t, int(datagrams.Load()), quicSent+counted(d, ReasonTXFull), "each datagram is sent or tx_full")
	assert.Equal(t, frames, f.frames(), "no frame is lost")
	assert.Equal(t, frames, f.NumFreeFrames()+f.NumCompleted(), "the kernel gave back all frames")
	t.Logf("QUIC datagrams %d, sent %d, tx_full %d; loop frames sent %d, full %d",
		datagrams.Load(), quicSent, counted(d, ReasonTXFull), loopSent.Load(), loopFull.Load())
}
