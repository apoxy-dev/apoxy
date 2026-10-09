// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package relay

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/apoxy-dev/icx/filter"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/safchain/ethtool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// XDP actions.
const (
	xdpPASS     uint32 = 2
	xdpTX       uint32 = 3
	xdpREDIRECT uint32 = 4
)

const (
	xdpPort    = 6081
	testMaxLen = 1500
)

// A packet of an agent or of another relay with the largest inner packet must not
// be too long for the XDP program. It has the PSP overhead one time.
func TestXDPMaxLen(t *testing.T) {
	assert.Equal(t, testMaxLen, xdpMaxLen)
	assert.Equal(t, 40+8+40+1412, xdpMaxLen)
}

var (
	xdpRelayMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	xdpPeerMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	xdpAddrs    = []netip.Addr{netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("fd09::1")}
)

// xdpNS is a netns with a veth link rl0 that has 10.9.0.1/24 and fd09::1/64,
// and the neighbors 10.9.0.2 and fd09::2. A test run finds the ingress
// ifindex in the netns of the thread, so the programs run on its thread.
type xdpNS struct {
	ifindex int
	work    chan func()
}

func newXDPNS(t *testing.T) *xdpNS {
	t.Helper()
	ns := &xdpNS{work: make(chan func())}
	errc := make(chan error, 1)
	go func() {
		// The thread stays in the new netns, so it must exit with the goroutine.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		var err error
		ns.ifindex, err = setupXDPLink()
		errc <- err
		if err != nil {
			return
		}
		for fn := range ns.work {
			fn()
		}
	}()
	if err := <-errc; err != nil {
		t.Skipf("cannot set up the test netns: %v", err)
	}
	t.Cleanup(func() { close(ns.work) })
	return ns
}

func setupXDPLink() (int, error) {
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "rl0", HardwareAddr: xdpRelayMAC}, PeerName: "rl1"}
	if err := netlink.LinkAdd(veth); err != nil {
		return 0, err
	}
	for _, name := range []string{"lo", "rl0", "rl1"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return 0, err
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return 0, err
		}
	}
	l, err := netlink.LinkByName("rl0")
	if err != nil {
		return 0, err
	}
	for _, p := range []string{"10.9.0.1/24", "fd09::1/64"} {
		a, _ := netlink.ParseAddr(p)
		a.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(l, a); err != nil {
			return 0, err
		}
	}
	for _, ip := range []string{"10.9.0.2", "fd09::2"} {
		a := netip.MustParseAddr(ip)
		fam := netlink.FAMILY_V4
		if a.Is6() {
			fam = netlink.FAMILY_V6
		}
		n := &netlink.Neigh{LinkIndex: l.Attrs().Index, Family: fam, State: netlink.NUD_PERMANENT, IP: a.AsSlice(), HardwareAddr: xdpPeerMAC}
		if err := netlink.NeighAdd(n); err != nil {
			return 0, err
		}
	}
	for _, f := range []string{"/proc/sys/net/ipv4/conf/rl0/forwarding", "/proc/sys/net/ipv6/conf/rl0/forwarding"} {
		if err := os.WriteFile(f, []byte("1"), 0o644); err != nil {
			return 0, err
		}
	}
	return l.Attrs().Index, nil
}

// do runs fn on the thread of ns.
func (ns *xdpNS) do(fn func()) {
	done := make(chan struct{})
	ns.work <- func() {
		defer close(done)
		fn()
	}
	<-done
}

func (ns *xdpNS) run(t *testing.T, prog *ebpf.Program, frame []byte) (uint32, []byte) {
	t.Helper()
	opts := &ebpf.RunOptions{
		Data:    frame,
		DataOut: make([]byte, len(frame)+256),
		Context: struct{ Data, DataEnd, DataMeta, IngressIfindex, RxQueueIndex, EgressIfindex uint32 }{DataEnd: uint32(len(frame)), IngressIfindex: uint32(ns.ifindex)},
	}
	var ret uint32
	var err error
	ns.do(func() { ret, err = prog.Run(opts) })
	require.NoError(t, err)
	return ret, opts.DataOut
}

// setFeature turns a link feature of rl0 on or off.
func (ns *xdpNS) setFeature(t *testing.T, name string, on bool) {
	t.Helper()
	var err error
	ns.do(func() {
		var e *ethtool.Ethtool
		if e, err = ethtool.NewEthtool(); err != nil {
			return
		}
		defer e.Close()
		err = e.Change("rl0", map[string]bool{name: on})
	})
	require.NoError(t, err)
}

// pspFrame returns an Ethernet frame from src to dst with a PSP packet of
// size bytes and spi.
func pspFrame(t *testing.T, src, dst netip.AddrPort, size int, spi uint32) []byte {
	t.Helper()
	p := make([]byte, size)
	p[0], p[1], p[2], p[3] = 4, 2, 2, 0x03
	binary.BigEndian.PutUint32(p[4:8], spi)
	eth := &layers.Ethernet{SrcMAC: xdpPeerMAC, DstMAC: xdpRelayMAC, EthernetType: layers.EthernetTypeIPv4}
	udp := &layers.UDP{SrcPort: layers.UDPPort(src.Port()), DstPort: layers.UDPPort(dst.Port())}
	var ip gopacket.NetworkLayer = &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src.Addr().AsSlice(), DstIP: dst.Addr().AsSlice()}
	if src.Addr().Is6() {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip = &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: src.Addr().AsSlice(), DstIP: dst.Addr().AsSlice()}
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip.(gopacket.SerializableLayer), udp, gopacket.Payload(p)))
	return buf.Bytes()
}

// TestXDPForward runs the XDP program with the rows that a router keeps.
func TestXDPForward(t *testing.T) {
	cases := []struct {
		name       string
		snd, rcv   string
		relay      string
		size       int // PSP packet size. Default 200.
		hop        time.Duration
		redirect   bool
		unregister bool
		want       uint32
	}{
		{name: "IPv4", snd: "192.0.2.1:1000", rcv: "10.9.0.2:2000", relay: "10.9.0.1", want: xdpTX},
		{name: "IPv6", snd: "[2001:db8::7]:1000", rcv: "[fd09::2]:2000", relay: "fd09::1", want: xdpTX},
		{name: "IPv4 with a kept next hop", snd: "192.0.2.1:1000", rcv: "10.9.0.2:2000", relay: "10.9.0.1", hop: time.Minute, want: xdpTX},
		{name: "IPv6 with a kept next hop", snd: "[2001:db8::7]:1000", rcv: "[fd09::2]:2000", relay: "fd09::1", hop: time.Minute, want: xdpTX},
		{name: "IPv4 with a redirect", snd: "192.0.2.1:1000", rcv: "10.9.0.2:2000", relay: "10.9.0.1", redirect: true, want: xdpREDIRECT},
		{name: "IPv6 with a redirect and a kept next hop", snd: "[2001:db8::7]:1000", rcv: "[fd09::2]:2000", relay: "fd09::1", hop: time.Minute, redirect: true, want: xdpREDIRECT},
		{name: "unregistered SPI", snd: "192.0.2.1:1000", rcv: "10.9.0.2:2000", relay: "10.9.0.1", unregister: true, want: xdpPASS},
		{name: "no neighbor", snd: "192.0.2.1:1000", rcv: "10.9.0.77:2000", relay: "10.9.0.1", want: xdpPASS},
		{name: "not a relay address", snd: "192.0.2.1:1000", rcv: "10.9.0.2:2000", relay: "10.9.0.9", want: xdpPASS},
		{name: "above the length bound", snd: "192.0.2.1:1000", rcv: "10.9.0.2:2000", relay: "10.9.0.1", size: testMaxLen, want: xdpPASS},
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ns := newXDPNS(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{LaneRate: 1e9, TunnelRate: 1e9})
			prog, err := r.newXDPProgram(XDPConfig{Port: xdpPort, NextHopCache: tc.hop}, testMaxLen, tc.redirect)
			if errors.Is(err, unix.EPERM) {
				t.Skipf("cannot load BPF programs: %v", err)
			}
			require.NoError(t, err)
			t.Cleanup(func() { _ = prog.Close() })
			require.NoError(t, prog.SetAddrs(xdpAddrs))
			r.setXDP(relayTable{p: prog}, time.Now())
			snd := addSession(t, r, vpcA, "sender", tc.snd, "fd00::1/128")
			addSession(t, r, vpcA, "receiver", tc.rcv, "fd00::2/128")
			require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 7), time.Now()))
			if tc.unregister {
				require.NoError(t, r.unregisterSPI(snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{7}}))
			}
			flushXDP(r, time.Now())

			src := netip.MustParseAddrPort(tc.snd)
			relay := netip.AddrPortFrom(netip.MustParseAddr(tc.relay), xdpPort)
			size := tc.size
			if size == 0 {
				size = 200
			}
			ret, out := ns.run(t, prog.Program(), pspFrame(t, src, relay, size, 7))
			require.Equal(t, tc.want, ret)
			if ret == xdpPASS {
				return
			}
			pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			var gotSrc, gotDst netip.Addr
			if ip, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
				gotSrc, _ = netip.AddrFromSlice(ip.SrcIP)
				gotDst, _ = netip.AddrFromSlice(ip.DstIP)
			} else {
				ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				gotSrc, _ = netip.AddrFromSlice(ip.SrcIP)
				gotDst, _ = netip.AddrFromSlice(ip.DstIP)
			}
			udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			assert.Equal(t, relay, netip.AddrPortFrom(gotSrc.Unmap(), uint16(udp.SrcPort)))
			assert.Equal(t, tc.rcv, netip.AddrPortFrom(gotDst.Unmap(), uint16(udp.DstPort)).String())
			assert.Equal(t, xdpPeerMAC, pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).DstMAC)

			lanes := r.SenderStats(snd.Session).Lanes
			require.Len(t, lanes, 1)
			assert.Equal(t, uint64(1), lanes[0].Packets)
			assert.Equal(t, uint64(200), lanes[0].Bytes)
		})
	}
}

// TestFlushesEachTX checks which drivers get a program that sends with a redirect.
func TestFlushesEachTX(t *testing.T) {
	cases := []struct {
		name   string
		driver string
		want   bool
	}{
		{name: "ena", driver: "ena", want: true},
		{name: "veth", driver: "veth"},
		{name: "mlx5", driver: "mlx5_core"},
		{name: "no driver name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, flushesEachTX(tc.driver))
		})
	}
}

// TestStartXDP attaches the program to a link and behind the Geneve program.
func TestStartXDP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ns := newXDPNS(t)
	cases := []struct {
		name    string
		iface   string
		generic bool
		chain   bool
		geneve  int    // Attach the Geneve program to rl0 with these flags; -1 for none.
		gro     string // Turn this link feature on.
		mode    string
		wantErr bool
	}{
		{name: "driver mode on veth", iface: "rl0", geneve: -1, mode: "driver"},
		{name: "driver mode with GRO forwarding", iface: "rl0", geneve: -1, gro: "rx-udp-gro-forwarding", mode: "driver"},
		{name: "generic mode", iface: "rl0", generic: true, geneve: -1, mode: "generic"},
		{name: "generic mode with GRO forwarding", iface: "rl0", generic: true, geneve: -1, gro: "rx-udp-gro-forwarding", wantErr: true},
		{name: "generic mode with GRO lists", iface: "rl0", generic: true, geneve: -1, gro: "rx-gro-list", wantErr: true},
		{name: "chain", iface: "rl0", chain: true, mode: "chain"},
		{name: "chain in generic mode", iface: "rl0", chain: true, geneve: unix.XDP_FLAGS_SKB_MODE, mode: "chain"},
		{name: "chain in generic mode with GRO forwarding", iface: "rl0", chain: true, geneve: unix.XDP_FLAGS_SKB_MODE, gro: "rx-udp-gro-forwarding", wantErr: true},
		{name: "chain with no program on the link", iface: "rl0", chain: true, geneve: -1, wantErr: true},
		{name: "no link", iface: "nope", geneve: -1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			cfg := XDPConfig{Port: xdpPort, Iface: tc.iface, Generic: tc.generic}
			if tc.gro != "" {
				ns.setFeature(t, tc.gro, true)
				t.Cleanup(func() { ns.setFeature(t, tc.gro, false) })
			}
			var chained []*ebpf.Program
			if tc.chain {
				cfg.Chain = func(p *ebpf.Program) error {
					chained = append(chained, p)
					return nil
				}
			}
			if tc.geneve >= 0 {
				g, err := filter.Geneve(&net.UDPAddr{IP: xdpAddrs[0].AsSlice(), Port: xdpPort})
				if errors.Is(err, unix.EPERM) {
					t.Skipf("cannot load BPF programs: %v", err)
				}
				require.NoError(t, err)
				filter.AttachFlags = tc.geneve
				ns.do(func() { err = g.Attach(ns.ifindex) })
				require.NoError(t, err)
				t.Cleanup(func() {
					ns.do(func() { _ = g.Detach(ns.ifindex) })
					filter.AttachFlags = 0
					_ = g.Close()
				})
			}
			var x *XDP
			var mode string
			var err error
			ns.do(func() { x, mode, err = r.StartXDP(cfg) })
			if errors.Is(err, unix.EPERM) {
				t.Skipf("cannot load BPF programs: %v", err)
			}
			if tc.wantErr {
				assert.Error(t, err)
				assert.Empty(t, chained)
				r.mu.RLock()
				assert.Nil(t, r.xdp)
				r.mu.RUnlock()
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.mode, mode)
			// The link features are read again only in generic mode.
			assert.Equal(t, tc.generic || tc.geneve == unix.XDP_FLAGS_SKB_MODE, x.joins != nil)
			r.mu.RLock()
			assert.NotNil(t, r.xdp)
			r.mu.RUnlock()
			ns.do(func() { err = x.Close() })
			require.NoError(t, err)
			r.mu.RLock()
			assert.Nil(t, r.xdp)
			r.mu.RUnlock()
			if tc.chain {
				require.Len(t, chained, 2)
				assert.NotNil(t, chained[0])
				assert.Nil(t, chained[1])
			}
		})
	}
}

// TestXDPRecheck takes the rows out while the link joins UDP packets and puts
// them back when it stops.
func TestXDPRecheck(t *testing.T) {
	const snd, rcv = "192.0.2.1:1000", "192.0.2.2:2000"
	both := map[string]string{snd + "/1": rcv, snd + "/2": rcv}
	none := map[string]string{}
	steps := []struct {
		name    string
		feature string // The link feature that is on.
		sweep   bool
		want    map[string]string
	}{
		{name: "rows in", want: both},
		{name: "join turns on", feature: "rx-gro-list", want: none},
		{name: "sweep keeps the rows out", feature: "rx-gro-list", sweep: true, want: none},
		{name: "join turns off", want: both},
		{name: "forwarding feature turns on", feature: "rx-udp-gro-forwarding", want: none},
	}
	t0 := time.Now()
	r := NewRouter(nil, Config{})
	f := newFakeXDP()
	r.setXDP(f, t0)
	s := addSession(t, r, vpcA, "sender", snd, "fd00::1/128")
	addSession(t, r, vpcA, "receiver", rcv, "fd00::2/128")
	require.NoError(t, r.registerSPI(s.Session, register(vpcA, "fd00::2", time.Hour, 1, 2), t0))
	flushXDP(r, t0)
	feature := ""
	x := &XDP{r: r, iface: "rl0", joins: func() (string, error) { return feature, nil }}
	for _, st := range steps {
		feature = st.feature
		x.recheck(t0)
		if st.sweep {
			r.Sweep(t0)
		}
		assert.Equal(t, st.want, f.installed(), st.name)
	}
}
