// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/safchain/ethtool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

// xdpTX is the XDP action of a packet that the program sends on its link.
const xdpTX = 3

var (
	floodRelayMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	floodPeerMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	floodRelayAP  = netip.MustParseAddrPort("10.9.0.1:4443")
	floodSource   = netip.MustParseAddr("10.9.0.3")
	floodCounter  = netip.MustParseAddr("10.9.0.2")
)

// floodNS is a netns with a veth link fl0 that has 10.9.0.1/24 and the neighbor
// 10.9.0.2, the counter. All work in the netns runs on the thread of the netns.
type floodNS struct {
	ifindex int
	work    chan func()
}

func newFloodNS(t *testing.T) *floodNS {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ns := &floodNS{work: make(chan func())}
	errc := make(chan error, 1)
	go func() {
		// The thread stays in the new netns, so it must exit with the goroutine.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		var err error
		ns.ifindex, err = setupFloodLink()
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

func setupFloodLink() (int, error) {
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "fl0", HardwareAddr: floodRelayMAC}, PeerName: "fl1"}
	if err := netlink.LinkAdd(veth); err != nil {
		return 0, err
	}
	for _, name := range []string{"lo", "fl0", "fl1"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return 0, err
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return 0, err
		}
	}
	l, err := netlink.LinkByName("fl0")
	if err != nil {
		return 0, err
	}
	a, _ := netlink.ParseAddr(floodRelayAP.Addr().String() + "/24")
	if err := netlink.AddrAdd(l, a); err != nil {
		return 0, err
	}
	n := &netlink.Neigh{LinkIndex: l.Attrs().Index, Family: netlink.FAMILY_V4, State: netlink.NUD_PERMANENT, IP: floodCounter.AsSlice(), HardwareAddr: floodPeerMAC}
	if err := netlink.NeighAdd(n); err != nil {
		return 0, err
	}
	return l.Attrs().Index, os.WriteFile("/proc/sys/net/ipv4/conf/fl0/forwarding", []byte("1"), 0o644)
}

// do runs fn on the thread of ns.
func (ns *floodNS) do(fn func()) {
	done := make(chan struct{})
	ns.work <- func() {
		defer close(done)
		fn()
	}
	<-done
}

// run runs prog on frame as a packet from fl0, and returns the action and the frame after it.
func (ns *floodNS) run(t *testing.T, prog *ebpf.Program, frame []byte) (uint32, []byte) {
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

// floodFrame returns the Ethernet frame of one packet of source port i, as the
// source sends it: the bytes of floodPayload in a UDP datagram from src to dst.
func floodFrame(t *testing.T, src netip.Addr, dst netip.AddrPort, i, size int, spi uint32) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: floodPeerMAC, DstMAC: floodRelayMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Flags: layers.IPv4DontFragment, Protocol: layers.IPProtocolUDP, SrcIP: src.AsSlice(), DstIP: dst.Addr().AsSlice()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(floodFirstPort + i), DstPort: layers.UDPPort(dst.Port())}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(floodPayload(size, 1, spi))))
	require.Len(t, buf.Bytes(), ethLen+size)
	return buf.Bytes()
}

// frameFlow returns the addresses and the destination MAC of an IPv4 UDP frame.
func frameFlow(t *testing.T, frame []byte) (src, dst netip.AddrPort, mac net.HardwareAddr) {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	ip, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	require.True(t, ok)
	udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	require.True(t, ok)
	s, _ := netip.AddrFromSlice(ip.SrcIP)
	d, _ := netip.AddrFromSlice(ip.DstIP)
	return netip.AddrPortFrom(s, uint16(udp.SrcPort)), netip.AddrPortFrom(d, uint16(udp.DstPort)), pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).DstMAC
}

// TestFloodRelayForward runs the packets of the source through the relay program
// that the bench loads, alone and behind the Geneve program.
func TestFloodRelayForward(t *testing.T) {
	ns := newFloodNS(t)
	hello := &floodHello{ID: "t", Ports: 32, FirstPort: floodFirstPort, Next: floodCounter.String(), NextPorts: 16, FirstNext: floodFirstNext}
	cases := []struct {
		name string
		mode string
		// tunnelRate is the tunnel limit of each sender in bits per second.
		tunnelRate float64
		port, size int
		spi        uint32
		// packets is the number of test runs. Default 1.
		packets int
		want    uint32
		// wantDrops are the least packets that the tunnel limit drops.
		wantDrops int
	}{
		{name: "800 bytes", mode: "generic", port: 0, size: 800, spi: floodSPI, want: xdpTX},
		{name: "smallest packet of the second sender", mode: "generic", port: 17, size: floodMinSize, spi: floodSPI + 1, want: xdpTX},
		{name: "largest packet", mode: "generic", port: 31, size: floodMaxLen, spi: floodSPI + 1, want: xdpTX},
		{name: "behind the Geneve program", mode: "chain", port: 5, size: 800, spi: floodSPI, want: xdpTX},
		{name: "smallest packet behind the Geneve program", mode: "chain", port: 16, size: floodMinSize, spi: floodSPI + 1, want: xdpTX},
		{name: "SPI of a different sender", mode: "generic", port: 0, size: 800, spi: floodSPI + 1, want: xdpPass},
		{name: "port with no row", mode: "generic", port: 32, size: 800, spi: floodSPI + 2, want: xdpPass},
		{name: "tunnel limit that drops no packet", mode: "generic", tunnelRate: 1e11, port: 3, size: 800, spi: floodSPI, packets: 200, want: xdpTX},
		// The burst is 64 KiB, and 200 packets have 154 kB of UDP payload.
		{name: "tunnel limit below the rate", mode: "generic", tunnelRate: 8e3, port: 3, size: 800, spi: floodSPI, packets: 200, want: xdpTX, wantDrops: 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := floodOptions{ID: "t", XDP: "fl0", XDPMode: tc.mode, TunnelRate: tc.tunnelRate}
			var x *floodXDP
			var err error
			ns.do(func() { x, err = startFloodXDP(o, floodRelayAP) })
			if errors.Is(err, unix.EPERM) {
				t.Skipf("cannot load BPF programs: %v", err)
			}
			require.NoError(t, err)
			t.Cleanup(func() { ns.do(func() { assert.NoError(t, x.close()) }) })
			assert.Equal(t, tc.mode, x.link.XDPMode)
			assert.Equal(t, uint32(floodMaxLen), x.link.MaxLen)
			assert.False(t, x.link.Redirect, "a veth link sends with XDP_TX")
			next, err := x.putRows(o, floodSource, hello)
			require.NoError(t, err)
			assert.Equal(t, floodCounter, next)

			prog := x.prog.Program()
			if tc.mode == "chain" {
				prog = x.geneve.Program
			}
			frame := floodFrame(t, floodSource, floodRelayAP, tc.port, tc.size, tc.spi)
			ret, out := ns.run(t, prog, frame)
			require.Equal(t, tc.want, ret)
			st, err := x.prog.Stats()
			require.NoError(t, err)
			if tc.want == xdpPass {
				assert.Equal(t, uint64(1), st.NoRow)
				assert.Zero(t, st.Packets)
				return
			}
			src, dst, mac := frameFlow(t, out)
			assert.Equal(t, floodRelayAP, src)
			assert.Equal(t, netip.AddrPortFrom(floodCounter, floodNext(tc.port, hello.NextPorts)), dst)
			assert.Equal(t, floodPeerMAC, mac)
			// The relay keeps the bytes of the PSP packet.
			assert.Equal(t, frame[ethLen+ipv4Len+udpLen:], out[ethLen+ipv4Len+udpLen:len(frame)])

			drops := 0
			for range max(tc.packets, 1) - 1 {
				if ret, _ := ns.run(t, prog, frame); ret == xdpDrop {
					drops++
				}
			}
			st, err = x.prog.Stats()
			require.NoError(t, err)
			assert.GreaterOrEqual(t, drops, tc.wantDrops)
			assert.Equal(t, uint64(drops), st.TunnelDrops)
			if tc.wantDrops == 0 {
				assert.Zero(t, drops)
			}
			fwd := uint64(max(tc.packets, 1) - drops)
			assert.Equal(t, fwd, st.Packets)
			assert.Equal(t, fwd*uint64(tc.size-ipv4Len-udpLen), st.Bytes, "the program counts the UDP payload")
			rows := x.rows(floodSource, hello)
			require.Len(t, rows, hello.Ports)
			for i, n := range rows {
				if i == tc.port {
					assert.Equal(t, fwd, n, "row %d", i)
				} else {
					assert.Zero(t, n, "row %d", i)
				}
			}
		})
	}
}

// rodata returns the constants of a loaded program, which hold its config.
func rodata(p *ebpf.Program) ([]byte, error) {
	info, err := p.Info()
	if err != nil {
		return nil, err
	}
	ids, _ := info.MapIDs()
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, err
		}
		defer m.Close()
		mi, err := m.Info()
		if err != nil {
			return nil, err
		}
		if strings.Contains(mi.Name, "rodata") {
			return m.LookupBytes(uint32(0))
		}
	}
	return nil, errors.New("the program has no constants")
}

// TestFloodRelayConfig checks that the bench loads the relay program with the
// same config as the relay of the product does on the same link.
func TestFloodRelayConfig(t *testing.T) {
	ns := newFloodNS(t)
	cases := []struct {
		name    string
		product relay.Config
		hop     time.Duration
		bench   floodOptions
		differ  bool
	}{
		{name: "no limits"},
		{name: "next hop cache", hop: time.Second, bench: floodOptions{XDPHop: time.Second}},
		// The relay command has a tunnel limit of 5 Gbit/s with a burst of 100 ms.
		{name: "tunnel limit", product: relay.Config{TunnelRate: 625e6, TunnelBurst: 625e5}, bench: floodOptions{TunnelRate: 5e9}},
		{name: "small tunnel limit with the smallest burst", product: relay.Config{TunnelRate: 1e5, TunnelBurst: 64 << 10}, bench: floodOptions{TunnelRate: 8e5}},
		{name: "a different limit is a different config", product: relay.Config{TunnelRate: 625e6, TunnelBurst: 625e5}, differ: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var want, got []byte
			var err error
			ns.do(func() {
				var x *relay.XDP
				x, _, err = relay.NewRouter(nil, tc.product).StartXDP(relay.XDPConfig{Port: floodRelayAP.Port(), Iface: "fl0", Generic: true, NextHopCache: tc.hop})
				if err != nil {
					return
				}
				defer x.Close()
				var l netlink.Link
				if l, err = netlink.LinkByName("fl0"); err != nil {
					return
				}
				var p *ebpf.Program
				if p, err = ebpf.NewProgramFromID(ebpf.ProgramID(l.Attrs().Xdp.ProgId)); err != nil {
					return
				}
				defer p.Close()
				want, err = rodata(p)
			})
			if errors.Is(err, unix.EPERM) {
				t.Skipf("cannot load BPF programs: %v", err)
			}
			require.NoError(t, err)
			o := tc.bench
			o.XDP, o.XDPMode = "fl0", "generic"
			ns.do(func() {
				var x *floodXDP
				if x, err = startFloodXDP(o, floodRelayAP); err != nil {
					return
				}
				defer x.close()
				got, err = rodata(x.prog.Program())
			})
			require.NoError(t, err)
			require.NotEmpty(t, want)
			if tc.differ {
				assert.NotEqual(t, want, got)
				return
			}
			assert.Equal(t, want, got)
		})
	}
}

// TestFloodRelayConfigDriver checks the settings that come from the link.
func TestFloodRelayConfigDriver(t *testing.T) {
	cases := []struct {
		name         string
		mtu          int
		driver       string
		wantLen      uint32
		wantRedirect bool
	}{
		{name: "ena with the MTU for XDP", mtu: 3498, driver: "ena", wantLen: 1500, wantRedirect: true},
		{name: "ena with a large MTU", mtu: 9001, driver: "ena", wantLen: 1500, wantRedirect: true},
		{name: "veth", mtu: 1500, driver: "veth", wantLen: 1500},
		{name: "small MTU", mtu: 1280, driver: "mlx5_core", wantLen: 1280},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := floodRelayConfig(floodOptions{}, 4443, tc.mtu, tc.driver)
			assert.Equal(t, uint16(4443), cfg.Port)
			assert.Equal(t, tc.wantLen, cfg.MaxLen)
			assert.Equal(t, tc.wantRedirect, cfg.Redirect)
			assert.Zero(t, cfg.LaneRate)
			assert.Zero(t, cfg.TunnelRate)
		})
	}
}

// TestReadKmsg writes records to the kernel log and reads them again.
func TestReadKmsg(t *testing.T) {
	fd := openKmsg()
	if fd < 0 {
		t.Skip("no access to /dev/kmsg")
	}
	defer unix.Close(fd)
	word := "vpcbench-flood-test-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile("/dev/kmsg", []byte(word+" one\n"), 0); err != nil {
		t.Skipf("write to /dev/kmsg: %v", err)
	}
	require.NoError(t, os.WriteFile("/dev/kmsg", []byte("a line with no word\n"), 0))
	got := readKmsg(fd, "", word)
	require.Len(t, got, 1)
	assert.True(t, strings.HasSuffix(got[0], " "+word+" one"), got[0])
	assert.Empty(t, readKmsg(fd, word))
	assert.Nil(t, readKmsg(-1, word))
}

// TestCountProg runs frames through the counter program.
func TestCountProg(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	c, err := newPortCounter(floodFirstNext, floodMaxNext)
	if errors.Is(err, unix.EPERM) {
		t.Skipf("cannot load BPF programs: %v", err)
	}
	require.NoError(t, err)
	defer c.close()
	frame := func(port, size int) []byte {
		return floodFrame(t, floodSource, netip.AddrPortFrom(floodCounter, uint16(port)), 0, size, floodSPI)
	}
	edit := func(f []byte, at int, v byte) []byte {
		f[at] = v
		return f
	}
	cases := []struct {
		name  string
		frame []byte
		want  uint32
		// port is the place of the port that gets the packet, with want xdpDrop.
		port int
	}{
		{name: "first port", frame: frame(floodFirstNext, 800), want: xdpDrop, port: 0},
		{name: "first port again", frame: frame(floodFirstNext, 800), want: xdpDrop, port: 0},
		{name: "last port with the smallest packet", frame: frame(floodFirstNext+floodMaxNext-1, floodMinSize), want: xdpDrop, port: floodMaxNext - 1},
		{name: "port below the first", frame: frame(floodFirstNext-1, 800), want: xdpPass},
		{name: "port above the last", frame: frame(floodFirstNext+floodMaxNext, 800), want: xdpPass},
		{name: "control port", frame: frame(4433, 800), want: xdpPass},
		{name: "TCP", frame: edit(frame(floodFirstNext, 800), ethLen+9, unix.IPPROTO_TCP), want: xdpPass},
		{name: "IPv4 with options", frame: edit(frame(floodFirstNext, 800), ethLen, 0x46), want: xdpPass},
		{name: "ARP", frame: edit(frame(floodFirstNext, 800), 13, 0x06), want: xdpPass},
		{name: "short frame", frame: frame(floodFirstNext, 800)[:ethLen+ipv4Len+udpLen-1], want: xdpPass},
	}
	want := make([]portCount, floodMaxNext)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ret, _, err := c.prog.Test(tc.frame)
			require.NoError(t, err)
			require.Equal(t, tc.want, ret)
			if tc.want == xdpDrop {
				want[tc.port].Packets++
				want[tc.port].Bytes += uint64(len(tc.frame))
			}
			pkts, bytes, err := c.read()
			require.NoError(t, err)
			for i, w := range want {
				require.Equal(t, w, portCount{pkts[i], bytes[i]}, "port %d", i)
			}
		})
	}
}

// TestFloodSender sends on loopback to sockets, and checks the packets that arrive.
func TestFloodSender(t *testing.T) {
	cases := []struct {
		name      string
		size, gso int
		batch     int
		targetPPS float64
	}{
		{name: "GSO messages", size: 800, gso: 64, batch: 16},
		{name: "one packet for each message", size: 800, gso: 1, batch: 16},
		{name: "smallest packet", size: floodMinSize, gso: 64, batch: 4},
		{name: "with a rate", size: 800, gso: 16, batch: 1, targetPPS: 20000},
	}
	local := netip.MustParseAddr("127.0.0.1")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const ports = 3
			seg := tc.size - ipv4Len - udpLen
			var got [ports]atomic.Uint64
			var bad atomic.Uint64
			var wg sync.WaitGroup
			var conns []*net.UDPConn
			for i := range ports {
				c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local.AsSlice()})
				require.NoError(t, err)
				require.NoError(t, c.SetReadBuffer(8<<20))
				conns = append(conns, c)
				wg.Go(func() {
					b := make([]byte, 1<<16)
					for {
						n, from, err := c.ReadFromUDPAddrPort(b)
						if err != nil {
							return
						}
						_, spi := senderOf(i)
						h, err := pspwire.ParseHeader(b[:n])
						if n != seg || err != nil || h.SPI != spi || int(from.Port()) != floodFirstPort+i {
							bad.Add(1)
							continue
						}
						got[i].Add(1)
					}
				})
			}
			dst := func(i int) netip.AddrPort { return conns[i].LocalAddr().(*net.UDPAddr).AddrPort() }
			run := floodRun{Size: tc.size, Ports: ports, NextPorts: ports, GSO: tc.gso, Batch: tc.batch, TargetPPS: tc.targetPPS}
			snd, err := newFloodSender(local, dst, run, 1<<20)
			require.NoError(t, err)
			defer snd.close()
			assert.Equal(t, "lo", snd.dev)
			assert.Equal(t, tc.gso, snd.segs, "loopback takes UDP GSO messages")
			const d = 300 * time.Millisecond
			sent, err := snd.send(context.Background(), d)
			require.NoError(t, err)
			assert.InDelta(t, d.Seconds(), sent.seconds, 0.2)
			assert.Zero(t, sent.errors)
			require.Len(t, sent.packets, ports)
			// The last packets are in the receive queues.
			time.Sleep(100 * time.Millisecond)
			for _, c := range conns {
				_ = c.Close()
			}
			wg.Wait()
			assert.Zero(t, bad.Load(), "packets with a wrong size, header or source port")
			var all uint64
			for i, n := range sent.packets {
				assert.Positive(t, n, "port %d", i)
				assert.Zero(t, n%uint64(tc.gso), "port %d sends full messages", i)
				// The first message of port 0 is the GSO test. A full receive buffer drops packets.
				assert.LessOrEqual(t, got[i].Load(), n+uint64(tc.gso), "port %d", i)
				assert.Positive(t, got[i].Load(), "port %d", i)
				all += n
			}
			if tc.targetPPS > 0 {
				assert.InDelta(t, tc.targetPPS*sent.seconds, float64(all), tc.targetPPS*sent.seconds/2)
			}
			m := snd.mark(time.Now())
			require.NotNil(t, m.Link)
			assert.Equal(t, "lo", m.Link.Dev)
			assert.NotEmpty(t, m.SNMP)
		})
	}
}

// floodChildEnv tells the test process that it runs in its own netns.
const floodChildEnv = "VPCBENCH_FLOOD_TEST_NETNS"

// TestFloodDirect runs the counter and the source with no relay on the loopback link of a
// new netns. The source threads must be in the netns, so the test runs again in a child process.
func TestFloodDirect(t *testing.T) {
	if os.Getenv(floodChildEnv) == "" {
		if os.Geteuid() != 0 {
			t.Skip("needs root")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestFloodDirect$", "-test.v")
		cmd.Env = append(os.Environ(), floodChildEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
		out, err := cmd.CombinedOutput()
		t.Logf("child:\n%s", out)
		require.NoError(t, err)
		if bytes.Contains(out, []byte("--- SKIP")) {
			t.Skip("the child skipped the test")
		}
		return
	}
	lo, err := netlink.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(lo))
	// The link must cut a GSO message into packets before the XDP program runs, as a NIC does.
	e, err := ethtool.NewEthtool()
	require.NoError(t, err)
	gsoErr := e.Change("lo", map[string]bool{"tx-udp-segmentation": false})
	e.Close()

	cases := []struct {
		name string
		size int
		gso  int
	}{
		{name: "one packet for each message", size: 800, gso: 1},
		{name: "GSO messages", size: 800, gso: 0},
		{name: "smallest packet", size: floodMinSize, gso: 0},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.gso != 1 && gsoErr != nil {
				t.Skipf("cannot turn off UDP segmentation on loopback: %v", gsoErr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			id := "direct-" + tc.name
			co := floodOptions{ID: id, Seq: i + 1, Listen: "127.0.0.1:0", XDP: "lo", XDPMode: "generic", StartTimeout: 30 * time.Second}
			addr := make(chan netip.AddrPort, 1)
			counterErr := make(chan error, 1)
			go func() { counterErr <- runFloodCounter(ctx, co, func(a netip.AddrPort) { addr <- a }) }()
			so := floodOptions{
				ID: id, Seq: i + 1, WorkDir: t.TempDir(), Size: tc.size, Ports: 4, NextPorts: 2, Batch: 4, GSO: tc.gso, Sndbuf: 1 << 20,
				Omit: 100 * time.Millisecond, Duration: 300 * time.Millisecond, Settle: 100 * time.Millisecond, StartTimeout: 30 * time.Second,
			}
			select {
			case a := <-addr:
				so.Server = a.String()
			case err := <-counterErr:
				if errors.Is(err, unix.EPERM) {
					t.Skipf("cannot load BPF programs: %v", err)
				}
				t.Fatalf("counter stopped: %v", err)
			}
			var out bytes.Buffer
			require.NoError(t, runFloodSource(ctx, so, &out))
			// The counter stops when the source disconnects.
			require.NoError(t, <-counterErr)

			var r floodResult
			require.NoError(t, json.Unmarshal(out.Bytes(), &r))
			assert.Equal(t, "direct", r.Via)
			assert.Nil(t, r.Relay)
			assert.Equal(t, tc.size, r.IPLen)
			assert.Equal(t, 4, r.Ports)
			if tc.gso == 1 {
				assert.Equal(t, 1, r.GSO)
			} else {
				assert.Equal(t, 64, r.GSO)
			}
			assert.InDelta(t, 0.3, r.Seconds, 0.2)
			assert.Positive(t, r.SentPPS)
			assert.Positive(t, r.PacketsPerSecond)
			// The backlog queue of the CPU can drop packets before the program runs.
			assert.LessOrEqual(t, r.PacketsPerSecond, r.SentPPS*1.001)
			assert.InDelta(t, float64(tc.size+ethLen)*8, r.BitsPerSecond/r.PacketsPerSecond, 1e-6, "the program counts single packets")
			require.Len(t, r.NextPortPPS, 2)
			assert.Positive(t, r.NextPortPPS[0])
			assert.Positive(t, r.NextPortPPS[1])
			assert.Zero(t, r.Counter.ICMPOut, "the counter host sends no ICMP error")
			require.NotNil(t, r.Counter.Link)
			assert.Equal(t, "generic", r.Counter.Link.XDPMode)
			b, err := os.ReadFile(so.WorkDir + "/flood-marks.json")
			require.NoError(t, err)
			var marks struct {
				ID      string
				Source  [2]*floodMark
				Counter [2]*floodMark
			}
			require.NoError(t, json.Unmarshal(b, &marks))
			assert.Equal(t, id, marks.ID)
			require.NotNil(t, marks.Counter[1])
			require.Len(t, marks.Counter[1].PortPkts, floodMaxNext)
			require.NotNil(t, marks.Source[1])
		})
	}
}
