// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	xipv4 "golang.org/x/net/ipv4"
	xipv6 "golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

var (
	relay4, peer4 = netip.MustParsePrefix("10.99.0.1/24"), netip.MustParsePrefix("10.99.0.2/24")
	relay6, peer6 = netip.MustParsePrefix("fd00:99::1/64"), netip.MustParsePrefix("fd00:99::2/64")
)

// env is a device on one end of a veth pair. The other end is in the netns peer, with the kernel.
type env struct {
	d       *dp.Device
	ifc     dp.Interface
	peer    netns.NsHandle
	packets chan *p4.PacketIn
	stop    func() // Stops the device and waits for Run.
}

// inNS runs fn on a thread in ns. The thread ends with fn, so it never runs other code in ns.
func inNS(t *testing.T, ns netns.NsHandle, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		if err := netns.Set(ns); err != nil {
			t.Errorf("set netns: %v", err)
			return
		}
		fn()
	}()
	<-done
}

// newEnv opens a device on a veth pair with the given number of queues on each end.
func newEnv(t *testing.T, queues int) *env {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for netns, veth and AF_XDP")
	}
	e := &env{packets: make(chan *p4.PacketIn, 64)}
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		e.peer, err = netns.New()
	}()
	<-done
	require.NoError(t, err)
	t.Cleanup(func() { e.peer.Close() })

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "rl0", MTU: 1500, NumTxQueues: queues, NumRxQueues: queues},
		PeerName:  "pe0", PeerNumTxQueues: uint32(queues), PeerNumRxQueues: uint32(queues),
	}
	require.NoError(t, netlink.LinkAdd(veth))
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	pe, err := netlink.LinkByName("pe0")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetNsFd(pe, int(e.peer)))
	rl, err := netlink.LinkByName("rl0")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(rl))

	h, err := netlink.NewHandleAt(e.peer)
	require.NoError(t, err)
	defer h.Close()
	for _, name := range []string{"lo", "pe0"} {
		l, err := h.LinkByName(name)
		require.NoError(t, err)
		require.NoError(t, h.LinkSetUp(l))
	}
	pe, err = h.LinkByName("pe0")
	require.NoError(t, err)
	for _, p := range []netip.Prefix{peer4, peer6} {
		a := &netlink.Addr{IPNet: &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}, Flags: unix.IFA_F_NODAD}
		require.NoError(t, h.AddrAdd(pe, a))
	}

	e.ifc = dp.Interface{Name: "rl0", MAC: rl.Attrs().HardwareAddr, Own: []netip.Prefix{relay4, relay6}}
	e.d, err = dp.OpenDevice(e.ifc)
	require.NoError(t, err)
	e.d.Target().OnPacketIn(func(p *p4.PacketIn) bool {
		select {
		case e.packets <- p:
			return true
		default:
			return false
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan error, 1)
	go func() { ran <- e.d.Run(ctx) }()
	e.stop = sync.OnceFunc(func() {
		cancel()
		assert.NoError(t, <-ran)
	})
	t.Cleanup(e.stop)
	return e
}

// listen opens a UDP socket of the peer.
func (e *env) listen(t *testing.T, addr netip.AddrPort) *net.UDPConn {
	t.Helper()
	var c *net.UDPConn
	var err error
	inNS(t, e.peer, func() { c, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr)) })
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func (e *env) drops(t *testing.T, reason uint8) int64 {
	return counts(t, e.d.Target(), dp.CounterDrops)[int64(reason)]
}

// ping sends ICMP echo requests from the peer to dst until a reply comes.
func (e *env) ping(t *testing.T, dst netip.Addr) {
	t.Helper()
	network, typ := "ip4:icmp", icmp.Type(xipv4.ICMPTypeEcho)
	proto := 1
	if dst.Is6() {
		network, typ, proto = "ip6:ipv6-icmp", xipv6.ICMPTypeEchoRequest, 58
	}
	var c *icmp.PacketConn
	var err error
	inNS(t, e.peer, func() { c, err = icmp.ListenPacket(network, "") })
	require.NoError(t, err)
	defer c.Close()
	req, err := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: 7, Seq: 1, Data: []byte("relay")}}).Marshal(nil)
	require.NoError(t, err)
	buf := make([]byte, 1500)
	for range 20 {
		_, err = c.WriteTo(req, &net.IPAddr{IP: dst.AsSlice()})
		require.NoError(t, err)
		require.NoError(t, c.SetReadDeadline(time.Now().Add(250*time.Millisecond)))
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				break
			}
			m, err := icmp.ParseMessage(proto, buf[:n])
			require.NoError(t, err)
			if m.Type == xipv4.ICMPTypeEchoReply || m.Type == xipv6.ICMPTypeEchoReply {
				assert.Equal(t, dst.String(), from.String())
				assert.Equal(t, []byte("relay"), m.Body.(*icmp.Echo).Data)
				return
			}
		}
	}
	t.Fatalf("no echo reply from %s", dst)
}

func TestDevice(t *testing.T) {
	e := newEnv(t, 1)

	// The first sends run before the peer sends anything, so the relay has no neighbor entry.
	t.Run("ARP and NDP before the first send", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			own  netip.Addr
			peer netip.AddrPort
		}{
			{name: "ARP", own: relay4.Addr(), peer: netip.AddrPortFrom(peer4.Addr(), 7001)},
			{name: "NDP", own: relay6.Addr(), peer: netip.AddrPortFrom(peer6.Addr(), 7001)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := e.listen(t, tc.peer)
				before := e.drops(t, dp.ReasonNoNeighbor)
				raw := &p4.PacketOut{Payload: []byte("raw"), Metadata: dp.PacketOutMeta{Kind: dp.KindRaw, To: tc.peer}.Metadata()}
				require.NoError(t, e.d.Target().PacketOut(raw))
				assert.Equal(t, before+1, e.drops(t, dp.ReasonNoNeighbor), "the first send has no neighbor")

				buf := make([]byte, 64)
				for range 40 {
					require.NoError(t, e.d.Target().PacketOut(raw))
					require.NoError(t, c.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
					n, from, err := c.ReadFromUDPAddrPort(buf)
					if err == nil {
						assert.Equal(t, "raw", string(buf[:n]))
						assert.Equal(t, netip.AddrPortFrom(tc.own, 1000), netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
						return
					}
				}
				t.Fatal("no datagram after ARP or NDP")
			})
		}
	})

	t.Run("demux", func(t *testing.T) {
		probeKey := [32]byte{1}
		probe := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{9}, Counter: 1}, 0, &probeKey)
		for _, tc := range []struct {
			name string
			run  func(t *testing.T)
		}{
			{name: "UDP 1000 to the pipeline", run: func(t *testing.T) {
				c := e.listen(t, netip.AddrPortFrom(peer4.Addr(), 7002))
				_, err := c.WriteToUDPAddrPort(probe, netip.AddrPortFrom(relay4.Addr(), 1000))
				require.NoError(t, err)
				select {
				case p := <-e.packets:
					md, err := dp.DecodePacketInMeta(p.GetMetadata())
					require.NoError(t, err)
					assert.Equal(t, dp.KindPunt, md.Kind)
					assert.Equal(t, netip.AddrPortFrom(peer4.Addr(), 7002), md.From)
					assert.Equal(t, probe, p.GetPayload())
				case <-time.After(5 * time.Second):
					t.Fatal("no PUNT of the probe")
				}
			}},
			{name: "UDP 443 to the QUIC conn, with ECN", run: func(t *testing.T) {
				for _, src := range []netip.AddrPort{netip.AddrPortFrom(peer4.Addr(), 7003), netip.AddrPortFrom(peer6.Addr(), 7003)} {
					c := e.listen(t, src)
					dst := netip.AddrPortFrom(relay4.Addr(), 443)
					if src.Addr().Is6() {
						dst = netip.AddrPortFrom(relay6.Addr(), 443)
						require.NoError(t, xipv6.NewConn(c).SetTrafficClass(0b10))
					} else {
						require.NoError(t, xipv4.NewConn(c).SetTOS(0b10))
					}
					_, err := c.WriteToUDPAddrPort([]byte("quic"), dst)
					require.NoError(t, err)
					conn := e.d.PacketConn().(quic.ECNPacketConn)
					require.NoError(t, e.d.PacketConn().SetReadDeadline(time.Now().Add(5*time.Second)))
					buf := make([]byte, 1500)
					n, from, ecn, err := conn.ReadFromECN(buf)
					require.NoError(t, err)
					assert.Equal(t, "quic", string(buf[:n]))
					assert.Equal(t, src, from.(*net.UDPAddr).AddrPort())
					assert.Equal(t, uint8(0b10), ecn, "ECT(0)")
				}
				require.NoError(t, e.d.PacketConn().SetReadDeadline(time.Time{}))
			}},
			{name: "ARP and ICMP to the netstack", run: func(t *testing.T) { e.ping(t, relay4.Addr()) }},
			{name: "NDP and ICMPv6 to the netstack", run: func(t *testing.T) { e.ping(t, relay6.Addr()) }},
			{name: "all else is dropped", run: func(t *testing.T) {
				before := e.drops(t, dp.ReasonDemux)
				c := e.listen(t, netip.AddrPortFrom(peer4.Addr(), 7004))
				for range 3 {
					_, err := c.WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(relay4.Addr(), 5000))
					require.NoError(t, err)
				}
				assert.Eventually(t, func() bool { return e.drops(t, dp.ReasonDemux) >= before+3 }, 5*time.Second, 10*time.Millisecond)
			}},
		} {
			t.Run(tc.name, tc.run)
		}
	})

	t.Run("DF and ECN of a QUIC conn send", func(t *testing.T) {
		conn := e.d.PacketConn().(quic.ECNPacketConn)
		for _, tc := range []struct {
			name string
			peer netip.AddrPort
			// recv returns the ECN bits and DF of the IP header of the next datagram to the peer.
			recv func(t *testing.T, c *net.UDPConn) (ecn uint8, df bool)
		}{
			{name: "IPv4", peer: netip.AddrPortFrom(peer4.Addr(), 7005), recv: func(t *testing.T, _ *net.UDPConn) (uint8, bool) {
				var pc net.PacketConn
				var err error
				inNS(t, e.peer, func() { pc, err = net.ListenPacket("ip4:udp", peer4.Addr().String()) })
				require.NoError(t, err)
				defer pc.Close()
				raw, err := xipv4.NewRawConn(pc)
				require.NoError(t, err)
				require.NoError(t, raw.SetReadDeadline(time.Now().Add(5*time.Second)))
				_, err = conn.WriteToECN([]byte("ecn"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(peer4.Addr(), 7005)), 0b01)
				require.NoError(t, err)
				h, _, _, err := raw.ReadFrom(make([]byte, 1500))
				require.NoError(t, err)
				return uint8(h.TOS) & 0b11, h.Flags&xipv4.DontFragment != 0
			}},
			{name: "IPv6", peer: netip.AddrPortFrom(peer6.Addr(), 7005), recv: func(t *testing.T, c *net.UDPConn) (uint8, bool) {
				pc := xipv6.NewPacketConn(c)
				require.NoError(t, pc.SetControlMessage(xipv6.FlagTrafficClass, true))
				require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
				_, err := conn.WriteToECN([]byte("ecn"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(peer6.Addr(), 7005)), 0b01)
				require.NoError(t, err)
				_, cm, _, err := pc.ReadFrom(make([]byte, 1500))
				require.NoError(t, err)
				// IPv6 has no DF field: routers never fragment.
				return uint8(cm.TrafficClass) & 0b11, true
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := e.listen(t, tc.peer)
				ecn, df := tc.recv(t, c)
				assert.Equal(t, uint8(0b01), ecn, "ECT(1)")
				assert.True(t, df, "DF")
			})
		}
	})

	t.Run("FRAME in and FRAME out on QUIC", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		conf := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 10 * time.Second}
		tr := &quic.Transport{Conn: e.d.PacketConn()}
		defer tr.Close()
		ln, err := tr.Listen(serverTLS(t), conf)
		require.NoError(t, err)
		defer ln.Close()

		// Two agents in VPC A, on ports 3 and 5 in QUIC mode.
		ports := []uint64{3, 5}
		agents := map[uint64]*quic.Conn{}
		var updates []*p4.Update
		for _, port := range ports {
			c := e.listen(t, netip.AddrPortFrom(peer4.Addr(), uint16(8000+port)))
			ctr := &quic.Transport{Conn: c}
			defer ctr.Close()
			agent, err := ctr.Dial(ctx, net.UDPAddrFromAddrPort(netip.AddrPortFrom(relay4.Addr(), 443)), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"relay"}}, conf)
			require.NoError(t, err)
			agents[port] = agent
			conn, err := ln.Accept(ctx)
			require.NoError(t, err)
			e.d.Target().SetFrameWriter(port, conn.TrySendDatagram)
			go func() { _ = dp.ReadFrames(ctx, e.d.Target(), conn, port, 1) }()
			p := fmt.Sprintf("100.64.%d.0/24", port)
			updates = append(updates,
				insert(dp.PortsKey{Port: port}.Entry(dp.PortAction{Session: 1, MTU: 1400, MeterIndex: uint32(port)})),
				insert(context_(port, 1, 0, vpcA, vniA, uint32(port))),
				insert(source(port, 1, 0, p, dp.NoAction{})),
				insert(route(vpcA, p, port, uint32(30+port), port, uint32(30+port))),
			)
		}
		require.NoError(t, write(ctx, e.d.Target(), updates...))

		for _, tc := range []struct {
			name     string
			from, to uint64
			inner    []byte
		}{
			{name: "port 3 to port 5", from: 3, to: 5, inner: ipv4("100.64.3.5", "100.64.5.5", 100)},
			{name: "port 5 to port 3", from: 5, to: 3, inner: ipv4("100.64.5.5", "100.64.3.5", 300)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				frame := peerconn.EncodeData(nil, vniA, tc.inner)
				require.NoError(t, agents[tc.from].SendDatagram(frame))
				got, err := agents[tc.to].ReceiveDatagram(ctx)
				require.NoError(t, err)
				assert.True(t, bytes.Equal(frame, got), "the frame out is the frame in")
			})
		}
	})
}

// TestDeviceReopen opens the link again right after the device stopped, as a relay that restarts.
// The kernel frees the AF_XDP queues of the stopped device a short time later.
func TestDeviceReopen(t *testing.T) {
	e := newEnv(t, 4)
	e.stop()
	d, err := dp.OpenDevice(e.ifc)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, d.Run(ctx))
}

// TestDeviceZeroCopy opens the link with each zero-copy setting. veth has native XDP but no
// zero-copy, so a device that demands zero-copy does not open. A device that runs has one named
// kicker thread for each TX queue.
func TestDeviceZeroCopy(t *testing.T) {
	const queues = 2
	e := newEnv(t, queues)
	e.stop()
	cases := []struct {
		name string
		zc   bool
		err  bool
	}{
		{name: "copy by default"},
		{name: "zero-copy", zc: true, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ifc := e.ifc
			ifc.ZeroCopy = tc.zc
			d, err := dp.OpenDevice(ifc)
			if tc.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			ran := make(chan error, 1)
			go func() { ran <- d.Run(ctx) }()
			assert.Eventually(t, func() bool { return kickThreads(t) == queues }, 5*time.Second, 10*time.Millisecond)
			cancel()
			require.NoError(t, <-ran)
		})
	}
}

// kickThreads returns the number of threads of this process with the name of a kicker.
func kickThreads(t *testing.T) int {
	tasks, err := os.ReadDir("/proc/self/task")
	require.NoError(t, err)
	n := 0
	for _, task := range tasks {
		comm, err := os.ReadFile("/proc/self/task/" + task.Name() + "/comm")
		if err == nil && string(bytes.TrimSpace(comm)) == dp.KickThread {
			n++
		}
	}
	return n
}

// fwd is agent A1 on the peer, at port 9001 and its lane ports, and the socket of agent A2 on the
// peer. The device forwards the PSP packets of A1 to A2.
type fwd struct {
	socks []*net.UDPConn // A1, then its lane ports.
	dst   *net.UDPConn
	buf   []byte
	seq   int // The last packet that send sent.
}

// forward writes the entries of A1 with the given number of lanes and of A2, which the device
// reaches at a2.
func (e *env) forward(t *testing.T, lanes int, a2 netip.AddrPort) *fwd {
	a1 := netip.AddrPortFrom(peer4.Addr(), 9001)
	var lanePorts uint64
	for lane := 1; lane < lanes; lane++ {
		lanePorts |= uint64(9010+lane) << (16 * (3 - lane))
	}
	updates := []*p4.Update{
		insert(access(1, a1, 7, lanePorts)),
		insert(access(2, a2, 8, 0)),
		insert(context_(1, 1, 0, vpcA, vniA, 1)),
		insert(context_(2, 1, 0, vpcA, vniA, 2)),
		insert(source(1, 1, 0, "100.64.1.0/24", dp.NoAction{})),
		insert(route(vpcA, "100.64.2.0/24", 2, 32, 2, 32)),
		tx(spiA2Out, 2, 1, 0),
	}
	f := &fwd{buf: make([]byte, 1500)}
	for lane := range lanes {
		updates = append(updates, rx(spiA1In+uint32(lane), 1, 1, uint32(lane)))
		from := a1
		if lane > 0 {
			from = netip.AddrPortFrom(a1.Addr(), uint16(9010+lane))
		}
		f.socks = append(f.socks, e.listen(t, from))
	}
	require.NoError(t, write(t.Context(), e.d.Target(), updates...))
	f.dst = e.listen(t, netip.AddrPortFrom(peer4.Addr(), 9002))
	require.NoError(t, f.dst.SetReadBuffer(1<<20))
	return f
}

// inner is packet seq of lane, with the lane and seq in its UDP payload.
func inner(lane, seq int) []byte {
	b := ipv4("100.64.1.5", "100.64.2.5", 100)
	b[28], b[29] = byte(lane), byte(seq)
	return b
}

func (f *fwd) send(t *testing.T, lane, seq int) {
	_, err := f.socks[lane].WriteToUDPAddrPort(seal(spiA1In+uint32(lane), vniA, uint32(seq), inner(lane, seq)), netip.AddrPortFrom(relay4.Addr(), 1000))
	require.NoError(t, err)
	f.seq = seq
}

// recv returns the inner packet of the next datagram to A2, or nil after wait.
func (f *fwd) recv(t *testing.T, wait time.Duration) []byte {
	require.NoError(t, f.dst.SetReadDeadline(time.Now().Add(wait)))
	n, from, err := f.dst.ReadFromUDPAddrPort(f.buf)
	if err != nil {
		return nil
	}
	assert.Equal(t, netip.AddrPortFrom(relay4.Addr(), 1000), netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
	spi, vni, payload := opened(t, f.buf[:n])
	assert.Equal(t, uint32(spiA2Out), spi)
	assert.Equal(t, uint32(vniA), vni)
	return payload
}

// arrive sends packets of A1 until one arrives at A2, for at most wait, and then reads all that
// arrive. It returns false when no packet arrived.
func (f *fwd) arrive(t *testing.T, wait time.Duration) bool {
	for end := time.Now().Add(wait); time.Now().Before(end); {
		f.send(t, 0, f.seq+1)
		if f.recv(t, 50*time.Millisecond) != nil {
			for f.recv(t, 100*time.Millisecond) != nil {
			}
			return true
		}
	}
	return false
}

// TestDeviceForward sends PSP packets of four lanes of an agent through a device with four queues.
// Each packet arrives at the target, sealed with the key of the target.
func TestDeviceForward(t *testing.T) {
	const flows, packets = 4, 50
	e := newEnv(t, flows)
	f := e.forward(t, flows, netip.AddrPortFrom(peer4.Addr(), 9002))
	require.True(t, f.arrive(t, 2*time.Second), "no packet after ARP")

	first := f.seq + 1
	want := map[string]bool{}
	for i := range packets {
		for lane := range flows {
			f.send(t, lane, first+i)
			want[string(inner(lane, first+i))] = true
		}
	}
	for len(want) > 0 {
		got := f.recv(t, 5*time.Second)
		require.NotNil(t, got, "%d packets did not arrive", len(want))
		delete(want, string(got))
	}
}

// TestDeviceNextHop sends packets to the MAC of the next hop, from the pipeline and from the QUIC
// conn. The device asks gVisor for a MAC again after at most 1 s, so a new MAC of the peer applies,
// and a next hop with no MAC drops.
func TestDeviceNextHop(t *testing.T) {
	cases := []struct {
		name   string
		a2     netip.AddrPort
		quic   bool // The QUIC conn sends to A2, else the pipeline forwards the packets of A1.
		newMAC bool // The peer takes a new MAC after the first packets arrive.
		want   bool // The packets arrive at A2, else they drop (no_neighbor).
	}{
		{name: "MAC of the peer", a2: netip.AddrPortFrom(peer4.Addr(), 9002), want: true},
		{name: "new MAC of the peer", a2: netip.AddrPortFrom(peer4.Addr(), 9002), newMAC: true, want: true},
		{name: "no neighbor", a2: netip.MustParseAddrPort("10.99.0.99:9002")},
		{name: "new MAC of the peer, QUIC conn", a2: netip.AddrPortFrom(peer4.Addr(), 9002), quic: true, newMAC: true, want: true},
		{name: "no neighbor, QUIC conn", a2: netip.MustParseAddrPort("10.99.0.99:9002"), quic: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, 1)
			f := e.forward(t, 1, tc.a2)
			arrive := f.arrive
			if tc.quic {
				// arrive sends from the QUIC conn until a datagram arrives at A2, for at most wait.
				arrive = func(t *testing.T, wait time.Duration) bool {
					for end := time.Now().Add(wait); time.Now().Before(end); {
						_, err := e.d.PacketConn().WriteTo([]byte("quic"), net.UDPAddrFromAddrPort(tc.a2))
						require.NoError(t, err)
						require.NoError(t, f.dst.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
						if _, _, err := f.dst.ReadFromUDPAddrPort(f.buf); err == nil {
							return true
						}
					}
					return false
				}
			}
			if tc.newMAC {
				// The peer sends first, as to a real relay. When gVisor resolves the peer itself,
				// -race finds a race in gVisor at the MAC change.
				e.ping(t, relay4.Addr())
				require.True(t, arrive(t, 2*time.Second), "no packet with the first MAC")
				// The kernel of the peer then resolves the relay again for the ping, which gives gVisor
				// the new MAC. The QUIC conn only sends, so without the ping the peer does not.
				h, err := netlink.NewHandleAt(e.peer)
				require.NoError(t, err)
				defer h.Close()
				pe, err := h.LinkByName("pe0")
				require.NoError(t, err)
				require.NoError(t, h.LinkSetHardwareAddr(pe, net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x01}))
				e.ping(t, relay4.Addr())
			}
			before := e.drops(t, dp.ReasonNoNeighbor)
			assert.Equal(t, tc.want, arrive(t, 3*time.Second))
			if !tc.want {
				assert.Greater(t, e.drops(t, dp.ReasonNoNeighbor), before)
			}
		})
	}
}

// TestDeviceKick sends rounds of packets on each send path and reads all packets of a round before
// the next round. A send does not kick; the kicker of the TX queue kicks after each batch, so a
// round arrives in a few ms, not at the next poll of an idle RX goroutine (100 ms).
func TestDeviceKick(t *testing.T) {
	const rounds, burst = 40, 16
	e := newEnv(t, 4)
	quicPeer, rawPeer := netip.AddrPortFrom(peer4.Addr(), 7201), netip.AddrPortFrom(peer6.Addr(), 7202)
	qc, rc := e.listen(t, quicPeer), e.listen(t, rawPeer)
	e.reach(t, qc, quicPeer)
	e.reach(t, rc, rawPeer)
	f := e.forward(t, 4, netip.AddrPortFrom(peer4.Addr(), 9002))
	require.True(t, f.arrive(t, 2*time.Second), "no packet after ARP")

	// read returns the next datagram to c, or nil after 5 s.
	read := func(c *net.UDPConn) func(t *testing.T) []byte {
		buf := make([]byte, 1500)
		return func(t *testing.T) []byte {
			require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
			n, _, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return nil
			}
			return bytes.Clone(buf[:n])
		}
	}
	cases := []struct {
		name string
		send func(t *testing.T, seq int) []byte // Sends packet seq and returns the bytes that arrive.
		recv func(t *testing.T) []byte          // Returns the next packet that arrives, or nil.
	}{
		{
			name: "pipeline batches of four RX queues",
			send: func(t *testing.T, seq int) []byte {
				f.send(t, seq%4, seq)
				return inner(seq%4, seq)
			},
			recv: func(t *testing.T) []byte { return f.recv(t, 5*time.Second) },
		},
		{
			name: "QUIC conn",
			send: func(t *testing.T, seq int) []byte {
				b := fmt.Appendf(nil, "quic %d", seq)
				_, err := e.d.PacketConn().WriteTo(b, net.UDPAddrFromAddrPort(quicPeer))
				require.NoError(t, err)
				return b
			},
			recv: read(qc),
		},
		{
			name: "RAW PacketOut",
			send: func(t *testing.T, seq int) []byte {
				b := fmt.Appendf(nil, "raw %d", seq)
				po := &p4.PacketOut{Payload: b, Metadata: dp.PacketOutMeta{Kind: dp.KindRaw, To: rawPeer}.Metadata()}
				require.NoError(t, e.d.Target().PacketOut(po))
				return b
			},
			recv: read(rc),
		},
	}
	seq := f.seq
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var times []time.Duration
			for range rounds {
				start, want := time.Now(), map[string]bool{}
				for range burst {
					seq++
					want[string(tc.send(t, seq))] = true
				}
				for len(want) > 0 {
					got := tc.recv(t)
					require.NotNil(t, got, "%d packets of the round did not arrive", len(want))
					delete(want, string(got))
				}
				times = append(times, time.Since(start))
			}
			slices.Sort(times)
			assert.Less(t, times[len(times)/2], 20*time.Millisecond, "the median time of a round")
		})
	}
}

// TestDeviceQUICQueue sends bursts of datagrams to UDP 443 and reads them after each burst. The
// queue holds 1024 datagrams, and each datagram over that drops (quic_full). A read gives the RX
// frame of a datagram back, so the bursts can have more datagrams than the RX frames.
func TestDeviceQUICQueue(t *testing.T) {
	e := newEnv(t, 1)
	c := e.listen(t, netip.AddrPortFrom(peer4.Addr(), 7301))
	// The peer resolves the relay first. Else its kernel drops the first datagrams of a burst.
	e.ping(t, relay4.Addr())
	conn := e.d.PacketConn()
	buf := make([]byte, 1500)
	seq := 0
	cases := []struct {
		name          string
		bursts, burst int
		drops         int64 // The quic_full drops of each burst.
	}{
		{name: "bursts that fit, more datagrams than RX frames", bursts: 8, burst: 1000},
		{name: "a burst over the queue", bursts: 1, burst: 1100, drops: 76},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for range tc.bursts {
				before := e.drops(t, dp.ReasonQUICFull)
				first := seq + 1
				for i := range tc.burst {
					seq++
					_, err := c.WriteToUDPAddrPort(fmt.Appendf(nil, "q %d", seq), netip.AddrPortFrom(relay4.Addr(), 443))
					require.NoError(t, err)
					if i%64 == 63 {
						time.Sleep(time.Millisecond) // So that the veth of the peer drops none.
					}
				}
				// The device takes all datagrams of the burst before the first read.
				time.Sleep(200 * time.Millisecond)
				for i := first; i <= seq-int(tc.drops); i++ {
					require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
					n, _, err := conn.ReadFrom(buf)
					require.NoError(t, err, "datagram %d", i)
					require.Equal(t, fmt.Sprintf("q %d", i), string(buf[:n]))
				}
				require.NoError(t, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
				_, _, err := conn.ReadFrom(buf)
				require.ErrorIs(t, err, os.ErrDeadlineExceeded, "a datagram over the queue")
				assert.Equal(t, before+tc.drops, e.drops(t, dp.ReasonQUICFull))
			}
		})
	}
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
}

func serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"relay"}}
}
