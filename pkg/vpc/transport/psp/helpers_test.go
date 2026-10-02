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
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	os.Exit(m.Run())
}

const (
	testProject = "project-a"
	testVPC     = "vpc-a"
	testVNI     = 0x1234
)

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
	peer   *Peer
	v4, v6 netip.Addr
	other  *node

	// Set when the node sends through a relay.
	rc   dp.RelayClient
	sess *relay.Session
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
		n.peer, err = n.b.AddPeer(addrOf(n.other.tr))
		require.NoError(t, err)
		require.NoError(t, n.b.AddRoute(netip.PrefixFrom(n.other.v4, 32), n.peer))
		require.NoError(t, n.b.AddRoute(netip.PrefixFrom(n.other.v6, 128), n.peer))
	}
	return a, b
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

// give sends a key change to the sender node. With a relay, it registers the
// SPIs first, so that the relay knows each SPI before its first packet.
func give(sender *node, req keys.Request, now time.Time) error {
	if sender.rc != nil && len(req.SAs) > 0 {
		spis := make([]uint32, len(req.SAs))
		for i, sa := range req.SAs {
			spis[i] = sa.SPI
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := sender.rc.RegisterSPI(ctx, &dp.RegisterSPIRequest{
			Vpc:         &dp.VPCRef{ProjectId: testProject, VpcUid: testVPC},
			Destination: sender.other.v4.String(),
			Spis:        spis,
			ExpiresIn:   durationpb.New(req.SAs[0].ExpiresIn),
		})
		if err != nil {
			return err
		}
	}
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
	d := newDriver(b, c.deliver)
	b.drv.Store(d)
	defer b.drv.Store(nil)
	b.receive(pkt)
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

// fakeRelay is a relay on loopback: relay.Router for sessions and SPI rows,
// and a loop that forwards PSP packets by SPI.
type fakeRelay struct {
	r        *relay.Router
	tr       *quic.Transport
	ln       *quic.Listener
	ca       *testCA
	accepted chan *relay.Session
	q        chan relayPkt
	drops    atomic.Uint64
}

type relayPkt struct {
	b    []byte
	from netip.AddrPort
}

func newFakeRelay(t testing.TB) *fakeRelay {
	t.Helper()
	ca := newCA(t)
	fr := &fakeRelay{
		r:        relay.NewRouter(&fakeTrust{ca}, relay.Config{}),
		ca:       ca,
		accepted: make(chan *relay.Session, 1),
		q:        make(chan relayPkt, 1024),
	}
	fr.tr = newTransport(t, fr.handle)
	var err error
	fr.ln, err = fr.tr.Listen(fr.r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}), nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	mux := rpc.NewMux()
	dp.RegisterRelayServer(mux, &relay.Server{R: fr.r})
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			qc, err := fr.ln.Accept(ctx)
			if err != nil {
				return
			}
			conn := rpc.NewConn(qc, mux)
			s, err := fr.r.AddSession(conn)
			if err != nil {
				_ = qc.CloseWithError(1, err.Error())
				continue
			}
			go func() { _ = conn.Serve(ctx) }()
			select {
			case fr.accepted <- s:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		fr.forward(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = fr.ln.Close()
		<-done
		<-done
	})
	return fr
}

// handle queues a non-QUIC packet for forward without blocking.
func (fr *fakeRelay) handle(b []byte, from net.Addr) {
	select {
	case fr.q <- relayPkt{bytes.Clone(b), from.(*net.UDPAddr).AddrPort()}:
	default:
		fr.drops.Add(1)
	}
}

// forward sends each PSP packet to the receiver of its SPI row.
func (fr *fakeRelay) forward(ctx context.Context) {
	for {
		var p relayPkt
		select {
		case p = <-fr.q:
		case <-ctx.Done():
			return
		}
		if len(p.b) < 8 {
			fr.drops.Add(1)
			continue
		}
		dst, v := fr.r.Forward(p.from, binary.BigEndian.Uint32(p.b[4:8]), len(p.b), time.Now())
		if v != relay.Pass {
			fr.drops.Add(1)
			continue
		}
		if _, err := fr.tr.WriteTo(p.b, net.UDPAddrFromAddrPort(dst)); err != nil {
			fr.drops.Add(1)
		}
	}
}

// attach dials the relay session of n on the transport of n, and routes the
// addresses of n to it.
func (fr *fakeRelay) attach(t testing.TB, n *node, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	san := identity.ID{Project: testProject, VPC: testVPC, Agent: name}.String()
	qc, err := n.tr.Dial(ctx, net.UDPAddrFromAddrPort(addrOf(fr.tr)), &tls.Config{
		Certificates:       []tls.Certificate{fr.ca.issue(t, san)},
		InsecureSkipVerify: true,
		NextProtos:         []string{dp.ALPNRelay},
	}, &quic.Config{KeepAlivePeriod: 5 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	select {
	case n.sess = <-fr.accepted:
	case <-ctx.Done():
		t.Fatal("relay did not accept the session")
	}
	n.rc = dp.NewRelayClient(rpc.NewConn(qc, nil))
	require.NoError(t, fr.r.AddRoute(n.sess, netip.PrefixFrom(n.v4, 32), name))
	require.NoError(t, fr.r.AddRoute(n.sess, netip.PrefixFrom(n.v6, 128), name))
}

// newRelayPair returns two nodes whose peers are at the relay.
func newRelayPair(t testing.TB) (*node, *node, *fakeRelay) {
	t.Helper()
	fr := newFakeRelay(t)
	a, b := newPair(t)
	fr.attach(t, a, "a")
	fr.attach(t, b, "b")
	a.peer.SetAddr(addrOf(fr.tr))
	b.peer.SetAddr(addrOf(fr.tr))
	return a, b, fr
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
func quicPair(t testing.TB, x, y *quic.Transport) (quic.Connection, quic.Connection) {
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

// testCA signs agent certs.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func newCA(t testing.TB) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key}
}

// issue signs an agent cert with the URI SAN san.
func (ca *testCA) issue(t testing.TB, san string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	u, err := url.Parse(san)
	require.NoError(t, err)
	notBefore := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(identity.CertLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeTrust trusts one CA and revokes no agent.
type fakeTrust struct{ ca *testCA }

func (f *fakeTrust) AgentCA() (*x509.CertPool, error) {
	p := x509.NewCertPool()
	p.AddCert(f.ca.cert)
	return p, nil
}

func (f *fakeTrust) Revoked(string, string) ([]vpcv1alpha1.RevokedAgent, error) { return nil, nil }

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
	if err := s.CreateNIC(1, ep); err != nil {
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

func fullAddr(a netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}
}

func protoOf(a netip.Addr) tcpip.NetworkProtocolNumber {
	if a.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}
