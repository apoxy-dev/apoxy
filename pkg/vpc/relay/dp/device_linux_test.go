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
	peer    netns.NsHandle
	packets chan *p4.PacketIn
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

func newEnv(t *testing.T) *env {
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

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "rl0", MTU: 1500}, PeerName: "pe0"}
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

	e.d, err = dp.OpenDevice(dp.Interface{Name: "rl0", MAC: rl.Attrs().HardwareAddr, Own: []netip.Prefix{relay4, relay6}})
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
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, <-ran)
	})
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
	e := newEnv(t)

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
		agents := map[uint64]quic.Connection{}
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

func serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"relay"}}
}
