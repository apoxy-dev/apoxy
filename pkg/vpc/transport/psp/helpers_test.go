// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	os.Exit(m.Run())
}

const testVNI = 0x1234

// newTransport returns a QUIC transport on a loopback UDP socket, with h as
// its NonQUICPacketHandler.
func newTransport(t testing.TB, h func([]byte, net.Addr)) *quic.Transport {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp, NonQUICPacketHandler: h}
	t.Cleanup(func() {
		_ = tr.Close()
		_ = udp.Close()
	})
	return tr
}

// demuxTransport returns a transport with dm as its NonQUICPacketHandler and NonQUICBatchEnd.
func demuxTransport(t testing.TB, dm *Demux) *quic.Transport {
	tr := newTransport(t, dm.Handle)
	tr.NonQUICBatchEnd = dm.BatchEnd
	return tr
}

func addrOf(tr *quic.Transport) netip.AddrPort {
	a := tr.Conn.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

// node is one agent: a binding with a peer for the other agent.
type node struct {
	tr     *quic.Transport
	b      *Binding
	l      *Link
	peer   *Peer
	v4, v6 netip.Addr
	other  *node
}

// newPair returns two nodes. Each one routes the addresses of the other to
// its peer at the socket of the other. The nodes have no SAs yet.
func newPair(t testing.TB) (*node, *node) {
	t.Helper()
	return newPairMTU(t, 0)
}

// newPairMTU returns two nodes with the inner MTU mtu.
func newPairMTU(t testing.TB, mtu int) (*node, *node) {
	t.Helper()
	return newPairLanes(t, mtu, 1)
}

// newPairLanes returns two nodes with the inner MTU mtu. Each node adds the
// other as its relay, and receives from it on lanes SAs.
func newPairLanes(t testing.TB, mtu, lanes int) (*node, *node) {
	t.Helper()
	a := &node{v4: netip.MustParseAddr("10.0.0.1"), v6: netip.MustParseAddr("fd00::1")}
	b := &node{v4: netip.MustParseAddr("10.0.0.2"), v6: netip.MustParseAddr("fd00::2")}
	a.other, b.other = b, a
	for _, n := range []*node{a, b} {
		dm := &Demux{}
		n.tr = demuxTransport(t, dm)
		var err error
		n.b, err = New(Config{Transport: n.tr, Demux: dm, VNI: testVNI, MTU: mtu})
		require.NoError(t, err)
		t.Cleanup(func() { _ = n.b.Close() })
	}
	for _, n := range []*node{a, b} {
		var err error
		n.l, err = n.b.AddLink()
		require.NoError(t, err)
		n.peer, err = n.l.AddRelay(addrOf(n.other.tr))
		require.NoError(t, err)
		if lanes > 1 {
			receiveLanes(t, n.peer, lanes)
		}
		require.NoError(t, n.b.AddRoute(netip.PrefixFrom(n.other.v4, 32), n.peer))
		require.NoError(t, n.b.AddRoute(netip.PrefixFrom(n.other.v6, 128), n.peer))
	}
	return a, b
}

// receiveLanes makes p receive on lanes SAs, as the receive side of a relay
// with send lanes does. An agent receives from its relay on one lane.
func receiveLanes(t testing.TB, p *Peer, lanes int) {
	t.Helper()
	b := p.b
	rx, err := b.recv.NewPeer(keys.PeerConfig{VNI: b.vni, MTU: b.mtu, Lanes: lanes, Sources: p.l.routed})
	require.NoError(t, err)
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.peers, p.rx)
	p.rx.Revoke()
	p.rx = rx
	b.peers[rx] = p
}

// offer gives each node SAs from the other one.
func offer(t testing.TB, now time.Time, nodes ...*node) {
	t.Helper()
	for _, n := range nodes {
		req, err := n.peer.Offer(now)
		require.NoError(t, err)
		require.NoError(t, give(n.other, req, now))
	}
}

// give sends a key change to the sender node.
func give(sender *node, req keys.Request, now time.Time) error {
	refused, err := sender.peer.Apply(req, now)
	if err == nil && len(refused) > 0 {
		err = fmt.Errorf("refused SPIs %x", refused)
	}
	return err
}

// rekey runs Tick on each node at now and gives the updates to the senders.
func rekey(now time.Time, nodes ...*node) (int, error) {
	n := 0
	for _, x := range nodes {
		ups, err := x.b.Tick(now)
		if err != nil {
			return n, err
		}
		for _, u := range ups {
			if u.Peer != x.peer {
				return n, errors.New("update for an unknown peer")
			}
			if err := give(x.other, u.Request, now); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// fakeBatch is a read batch that gives each packet to a deliver function at once, and counts it
// as the batches of the drivers do. onAdd, when set, runs first in each add.
type fakeBatch struct {
	st      *counters
	deliver func([]byte, int) bool
	onAdd   func()
}

func (f *fakeBatch) add(pkt []byte) {
	if f.onAdd != nil {
		f.onAdd()
	}
	if f.deliver(pkt, 0) {
		f.st.rxPackets.Add(1)
	} else {
		f.st.rxDrops.Add(1)
	}
}

func (*fakeBatch) flush() {}

// fakeDriver returns a driver of b with deliver as its deliver function and its read batch. The
// tests that only send give a nil deliver.
func fakeDriver(b *Binding, deliver func([]byte, int) bool) *driver {
	d := newDriver(b, deliver)
	d.batch = &fakeBatch{st: &b.stats, deliver: deliver}
	return d
}

// laneRead gives a PSP packet to the read loop of the socket of lane: the demux for lane 0.
func laneRead(b *Binding, lane int, pkt []byte) {
	if lane == 0 {
		b.demux.Handle(pkt, nil)
		return
	}
	b.receive(&b.lanes[lane], pkt)
}

// laneEnd ends a read of the socket of lane.
func laneEnd(b *Binding, lane int) {
	if lane == 0 {
		b.demux.BatchEnd()
		return
	}
	b.readEnd(&b.lanes[lane])
}

// handlerFunc is a peerconn.DataHandler that gives each frame to a function.
type handlerFunc func([]byte)

func (h handlerFunc) HandleData(frame []byte) { h(frame) }
func (handlerFunc) BatchEnd()                 {}

// capture is a deliver function that keeps copies of the inner packets.
type capture struct {
	mu   sync.Mutex
	got  [][]byte
	fail bool
}

func (c *capture) deliver(buf []byte, off int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return false
	}
	c.got = append(c.got, bytes.Clone(buf[off:]))
	return true
}

// seal returns the send frame of pkt from n, or nil.
func seal(n *node, pkt []byte) []byte {
	phy := make([]byte, 2048)
	m, _ := (&driver{b: n.b}).VirtToPhy(pkt, phy)
	if m == 0 {
		return nil
	}
	return phy[:m]
}

// open gives a PSP packet to the receive path of b, and returns the inner
// packet or nil. b must have no driver.
func open(b *Binding, pkt []byte) []byte {
	c := &capture{}
	d := fakeDriver(b, c.deliver)
	b.drv.Store(d)
	defer b.drv.Store(nil)
	b.demux.Handle(pkt, nil)
	if len(c.got) == 0 {
		return nil
	}
	return c.got[0]
}

// packet returns an IPv4 or IPv6 packet with a UDP-like header.
func packet(src, dst netip.Addr, proto byte, sport, dport uint16, size int) []byte {
	if src.Is4() {
		p := make([]byte, size)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:], uint16(size))
		p[8], p[9] = 64, proto
		copy(p[12:16], src.AsSlice())
		copy(p[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(p[20:], sport)
		binary.BigEndian.PutUint16(p[22:], dport)
		return p
	}
	p := make([]byte, size)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(size-40))
	p[6], p[7] = proto, 64
	copy(p[8:24], src.AsSlice())
	copy(p[24:40], dst.AsSlice())
	binary.BigEndian.PutUint16(p[40:], sport)
	binary.BigEndian.PutUint16(p[42:], dport)
	return p
}

// selfSigned returns a cert for 127.0.0.1 that signs itself.
func selfSigned(t testing.TB) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// quicPair returns a QUIC connection with datagrams from x to y, and its end
// on y. It has the packet size of relay sessions.
func quicPair(t testing.TB, x, y *quic.Transport) (*quic.Conn, *quic.Conn) {
	t.Helper()
	conf := &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350}
	ln, err := y.Listen(&tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, NextProtos: []string{"test"}}, conf)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qx, err := x.Dial(ctx, y.Conn.LocalAddr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"test"}}, conf)
	require.NoError(t, err)
	t.Cleanup(func() { _ = qx.CloseWithError(0, "") })
	qy, err := ln.Accept(ctx)
	require.NoError(t, err)
	return qx, qy
}

// fakeTun is a TUN device in memory. Read returns the packets of in, and Write
// sends the packets to out.
type fakeTun struct {
	in, out chan []byte
	calls   []int // The number of packets in each Write.
	err     error
	closed  chan struct{}
	once    sync.Once
}

func newFakeTun(n int) *fakeTun {
	return &fakeTun{in: make(chan []byte, n), out: make(chan []byte, n), closed: make(chan struct{})}
}

func (f *fakeTun) Read(bufs [][]byte, sizes []int, off int) (int, error) {
	select {
	case p := <-f.in:
		sizes[0] = copy(bufs[0][off:], p)
		return 1, nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}

// Write writes over the space before each packet, as the real device does.
func (f *fakeTun) Write(bufs [][]byte, off int) (int, error) {
	f.calls = append(f.calls, len(bufs))
	if f.err != nil {
		return 0, f.err
	}
	for _, b := range bufs {
		if off < tunOffset || len(b) <= off {
			return 0, errors.New("no space before the packet")
		}
		clear(b[:off])
		select {
		case f.out <- bytes.Clone(b[off:]):
		default:
			return 0, errors.New("out is full")
		}
	}
	return len(bufs), nil
}

func (f *fakeTun) BatchSize() int { return 4 }

func (f *fakeTun) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// startNetstack runs a gVisor stack on the binding of n. A zero TCP window
// gives a UDP-only stack, because gVisor TCP uses all CPUs in race builds.
func startNetstack(t testing.TB, n *node, window int) *stack.Stack {
	t.Helper()
	protos := []stack.TransportProtocolFactory{udp.NewProtocol}
	if window > 0 {
		protos = append(protos, tcp.NewProtocol)
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: protos,
	})
	if window > 0 {
		sack := tcpip.TCPSACKEnabled(true)
		rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: window, Max: window}
		snd := tcpip.TCPSendBufferSizeRangeOption{Min: 64 << 10, Default: 2 << 20, Max: 16 << 20}
		for _, opt := range []tcpip.SettableTransportProtocolOption{&sack, &rcv, &snd} {
			if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
				t.Fatalf("set TCP option: %v", err)
			}
		}
	}
	ep := channel.New(4096, uint32(n.b.mtu), "")
	// TCP gives GSO packets to the driver, as in the netstack of the agent.
	ep.SupportedGSOKind = stack.HostGSOSupported
	if err := s.CreateNIC(1, gsoLink{ep}); err != nil {
		t.Fatalf("create NIC: %v", err)
	}
	for _, a := range []netip.Addr{n.v4, n.v6} {
		proto := ipv4.ProtocolNumber
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix()}
		if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("add address: %v", err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	d, err := n.b.Netstack(ep)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = n.b.Close()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("netstack driver did not stop")
		}
		s.Close()
	})
	return s
}

// gsoLink is a channel endpoint that takes TCP segments of up to 64 KiB.
type gsoLink struct{ *channel.Endpoint }

func (gsoLink) GSOMaxSize() uint32 { return 1<<16 - 1 }

func fullAddr(a netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}
}

func protoOf(a netip.Addr) tcpip.NetworkProtocolNumber {
	if a.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}
