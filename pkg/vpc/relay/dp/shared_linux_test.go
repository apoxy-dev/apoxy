// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp/aead"
)

const sharedMode = configv1alpha1.RelayInterfaceModeShared

// sendRaw sends a RAW PacketOut with payload to to.
func (e *env) sendRaw(t *testing.T, to netip.AddrPort, payload string) {
	t.Helper()
	raw := &p4.PacketOut{Payload: []byte(payload), Metadata: dp.PacketOutMeta{Kind: dp.KindRaw, To: to}.Metadata()}
	require.NoError(t, e.d.Target().PacketOut(raw))
}

// rawArrive sends RAW packets with payload to to until one arrives at c, for at most wait. It
// returns false when none arrived. It skips the datagrams with another payload.
func (e *env) rawArrive(t *testing.T, c *net.UDPConn, to netip.AddrPort, payload string, wait time.Duration) bool {
	t.Helper()
	own := relay4.Addr()
	if to.Addr().Is6() {
		own = relay6.Addr()
	}
	buf := make([]byte, 64)
	for end := time.Now().Add(wait); time.Now().Before(end); {
		e.sendRaw(t, to, payload)
		require.NoError(t, c.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			if string(buf[:n]) == payload {
				assert.Equal(t, netip.AddrPortFrom(own, dp.PortData), netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
				return true
			}
		}
	}
	return false
}

// kernelEntry returns the kernel neighbor entry of a on rl0, with the netlink handle h.
func kernelEntry(t *testing.T, h *netlink.Handle, a netip.Addr) (netlink.Neigh, bool) {
	t.Helper()
	l, err := h.LinkByName("rl0")
	require.NoError(t, err)
	family := netlink.FAMILY_V4
	if a.Is6() {
		family = netlink.FAMILY_V6
	}
	list, err := h.NeighList(l.Attrs().Index, family)
	require.NoError(t, err)
	for _, n := range list {
		if n.IP.Equal(a.AsSlice()) {
			return n, true
		}
	}
	return netlink.Neigh{}, false
}

// peerHandle is a netlink handle in the netns of the peer.
func (e *env) peerHandle(t *testing.T) *netlink.Handle {
	t.Helper()
	h, err := netlink.NewHandleAt(e.peer)
	require.NoError(t, err)
	t.Cleanup(h.Close)
	return h
}

// TestDeviceSharedNextHop sends RAW packets, and PSP packets through the pipeline, in Shared mode.
// The next-hop MACs come from the kernel neighbor table. A hop with no MAC drops (no_neighbor), and
// the device asks the kernel to resolve it.
func TestDeviceSharedNextHop(t *testing.T) {
	on4, on6 := netip.AddrPortFrom(peer4.Addr(), 9002), netip.AddrPortFrom(peer6.Addr(), 9002)
	// A handle with no sockets uses the netns of the calling thread: the netns of the test, with rl0.
	h := &netlink.Handle{}
	cases := []struct {
		name  string
		setup func(t *testing.T, e *env) // Runs before OpenDevice.
		run   func(t *testing.T, e *env)
	}{
		{name: "on-link peer, IPv4", run: firstSend(h, on4)},
		{name: "on-link peer, IPv6", run: firstSend(h, on6)},
		{name: "on-link peer, IPv4, through the pipeline", run: func(t *testing.T, e *env) {
			f := e.forward(t, 1, on4)
			assert.True(t, f.arrive(t, 3*time.Second))
		}},
		{name: "gateway, IPv4", run: viaGateway(h, netip.AddrPortFrom(off4.Addr(), 9002), gw4.Addr())},
		{name: "gateway, IPv6", run: viaGateway(h, netip.AddrPortFrom(off6.Addr(), 9002), gw6.Addr())},
		{
			name: "gateway, IPv6 link-local with a zone",
			setup: func(t *testing.T, e *env) {
				ph := e.peerHandle(t)
				pe, err := ph.LinkByName("pe0")
				require.NoError(t, err)
				require.NoError(t, ph.AddrAdd(pe, kernelAddr(netip.MustParsePrefix("fe80::fe/64"))))
				e.ifc.Gateways = []netip.Addr{gw4.Addr(), netip.MustParseAddr("fe80::fe%rl0")}
			},
			run: viaGateway(h, netip.AddrPortFrom(off6.Addr(), 9002), netip.MustParseAddr("fe80::fe")),
		},
		{name: "an entry that changes, IPv4", run: newPeerMAC(h, on4, relay4.Addr())},
		{name: "an entry that changes, IPv6", run: newPeerMAC(h, on6, relay6.Addr())},
		{name: "no entry, IPv4", run: noNeighbor(h, netip.MustParseAddrPort("10.99.0.99:9002"))},
		{name: "no entry, IPv6", run: noNeighbor(h, netip.MustParseAddrPort("[fd00:99::99]:9002"))},
		{name: "a NONE entry that the host makes after the open, IPv4", run: func(t *testing.T, e *env) {
			c := e.listen(t, on4)
			l, err := h.LinkByName("rl0")
			require.NoError(t, err)
			require.NoError(t, h.NeighAdd(&netlink.Neigh{LinkIndex: l.Attrs().Index, Family: netlink.FAMILY_V4, IP: peer4.Addr().AsSlice(), State: unix.NUD_NONE}))
			n, ok := kernelEntry(t, h, peer4.Addr())
			require.True(t, ok)
			require.Equal(t, unix.NUD_NONE, n.State)
			assert.True(t, e.rawArrive(t, c, on4, "raw", 3*time.Second))
		}},
		{name: "a FAILED entry, then the peer answers, IPv4", run: func(t *testing.T, e *env) {
			to := netip.MustParseAddrPort("10.99.0.97:9002")
			// The kernel sends 3 probes 200 ms apart, so the entry fails after about 600 ms.
			for conf, v := range map[string]string{"mcast_solicit": "3", "ucast_solicit": "3", "app_solicit": "0", "retrans_time_ms": "200"} {
				require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/neigh/rl0/"+conf, []byte(v), 0o644))
			}
			before := e.drops(t, dp.ReasonNoNeighbor)
			e.sendRaw(t, to, "raw")
			assert.Equal(t, before+1, e.drops(t, dp.ReasonNoNeighbor))
			require.Eventually(t, func() bool {
				n, ok := kernelEntry(t, h, to.Addr())
				return ok && n.State == unix.NUD_FAILED
			}, 5*time.Second, 20*time.Millisecond, "the entry is not FAILED")
			ph := e.peerHandle(t)
			pe, err := ph.LinkByName("pe0")
			require.NoError(t, err)
			require.NoError(t, ph.AddrAdd(pe, kernelAddr(netip.PrefixFrom(to.Addr(), 24))))
			c := e.listen(t, to)
			assert.True(t, e.rawArrive(t, c, to, "raw", 3*time.Second))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLink(t, 1, sharedMode)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			e.open(t)
			tc.run(t, e)
		})
	}
}

// firstSend checks that the first send to an on-link peer with no kernel entry drops
// (no_neighbor), and that later sends arrive.
func firstSend(h *netlink.Handle, to netip.AddrPort) func(t *testing.T, e *env) {
	return func(t *testing.T, e *env) {
		c := e.listen(t, to)
		_, ok := kernelEntry(t, h, to.Addr())
		require.False(t, ok, "a kernel entry at the start")
		before := e.drops(t, dp.ReasonNoNeighbor)
		e.sendRaw(t, to, "raw")
		assert.Equal(t, before+1, e.drops(t, dp.ReasonNoNeighbor), "the first send has no neighbor")
		assert.True(t, e.rawArrive(t, c, to, "raw", 3*time.Second))
	}
}

// viaGateway checks that a packet to an off-link target arrives through gw. The peer answers ARP
// and NDP for both, so only the kernel entries show that the device sent to gw.
func viaGateway(h *netlink.Handle, to netip.AddrPort, gw netip.Addr) func(t *testing.T, e *env) {
	return func(t *testing.T, e *env) {
		c := e.listen(t, to)
		require.True(t, e.rawArrive(t, c, to, "raw", 3*time.Second))
		n, ok := kernelEntry(t, h, gw)
		require.True(t, ok, "no entry for the gateway")
		assert.Len(t, n.HardwareAddr, 6)
		_, ok = kernelEntry(t, h, to.Addr())
		assert.False(t, ok, "an entry for the target")
	}
}

// newPeerMAC checks that packets arrive after the peer takes a new MAC and pings own from the
// target address, so that the relay kernel gets the new MAC of the target from the peer's request.
func newPeerMAC(h *netlink.Handle, to netip.AddrPort, own netip.Addr) func(t *testing.T, e *env) {
	return func(t *testing.T, e *env) {
		c := e.listen(t, to)
		require.True(t, e.rawArrive(t, c, to, "first MAC", 3*time.Second), "no packet with the first MAC")
		ph := e.peerHandle(t)
		pe, err := ph.LinkByName("pe0")
		require.NoError(t, err)
		mac := net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x01}
		require.NoError(t, ph.LinkSetHardwareAddr(pe, mac))
		e.pingFrom(t, to.Addr(), own)
		require.Eventually(t, func() bool {
			n, ok := kernelEntry(t, h, to.Addr())
			return ok && n.HardwareAddr.String() == mac.String()
		}, 3*time.Second, 20*time.Millisecond, "the kernel does not have the new MAC")
		assert.True(t, e.rawArrive(t, c, to, "new MAC", 3*time.Second), "no packet with the new MAC")
	}
}

// noNeighbor checks that sends to an on-link address that no host has drop (no_neighbor), and that
// the kernel gets an entry for the address, because the device asked it to resolve the address.
func noNeighbor(h *netlink.Handle, to netip.AddrPort) func(t *testing.T, e *env) {
	return func(t *testing.T, e *env) {
		_, ok := kernelEntry(t, h, to.Addr())
		require.False(t, ok, "a kernel entry at the start")
		before := e.drops(t, dp.ReasonNoNeighbor)
		for range 20 {
			e.sendRaw(t, to, "raw")
		}
		assert.Equal(t, before+20, e.drops(t, dp.ReasonNoNeighbor))
		assert.Eventually(t, func() bool {
			_, ok := kernelEntry(t, h, to.Addr())
			return ok
		}, 3*time.Second, 20*time.Millisecond, "the device did not ask the kernel")
	}
}

// TestDeviceSharedStartStop checks that the host keeps its TCP and ICMP before the device, while it
// runs in Shared mode, and after it stops, and that relay traffic works while it runs.
func TestDeviceSharedStartStop(t *testing.T) {
	e := newLink(t, 2, sharedMode)
	var echoes []netip.AddrPort
	for _, a := range []netip.Addr{relay4.Addr(), relay6.Addr()} {
		to := netip.AddrPortFrom(a, 7300)
		ln, err := net.Listen("tcp", to.String())
		require.NoError(t, err)
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_, _ = io.Copy(c, c)
				}()
			}
		}()
		echoes = append(echoes, to)
	}
	host := func(t *testing.T) {
		e.ping(t, relay4.Addr())
		e.ping(t, relay6.Addr())
		for _, to := range echoes {
			var c net.Conn
			var err error
			inNS(t, e.peer, func() { c, err = net.DialTimeout("tcp", to.String(), 3*time.Second) })
			require.NoError(t, err, "TCP to %s", to)
			defer c.Close()
			require.NoError(t, c.SetDeadline(time.Now().Add(3*time.Second)))
			_, err = c.Write([]byte("echo"))
			require.NoError(t, err)
			buf := make([]byte, 4)
			_, err = io.ReadFull(c, buf)
			require.NoError(t, err)
			assert.Equal(t, "echo", string(buf))
		}
	}
	t.Run("before the device", host)
	e.open(t)
	t.Run("while the device runs", func(t *testing.T) {
		host(t)
		probeKey := [32]byte{1}
		probe := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{9}, Counter: 1}, 0, &probeKey)
		for _, tc := range []struct{ from, to netip.AddrPort }{
			{from: netip.AddrPortFrom(peer4.Addr(), 7302), to: netip.AddrPortFrom(relay4.Addr(), dp.PortData)},
			{from: netip.AddrPortFrom(peer6.Addr(), 7302), to: netip.AddrPortFrom(relay6.Addr(), dp.PortData)},
		} {
			c := e.listen(t, tc.from)
			_, err := c.WriteToUDPAddrPort(probe, tc.to)
			require.NoError(t, err)
			select {
			case p := <-e.packets:
				md, err := dp.DecodePacketInMeta(p.GetMetadata())
				require.NoError(t, err)
				assert.Equal(t, dp.KindPunt, md.Kind)
				assert.Equal(t, tc.from, md.From)
				assert.Equal(t, probe, p.GetPayload())
			case <-time.After(5 * time.Second):
				t.Fatalf("no PUNT of the probe to %s", tc.to)
			}
		}
		c := e.listen(t, netip.AddrPortFrom(peer4.Addr(), 7303))
		_, err := c.WriteToUDPAddrPort([]byte("quic"), netip.AddrPortFrom(relay4.Addr(), 443))
		require.NoError(t, err)
		conn := e.d.PacketConn()
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		buf := make([]byte, 64)
		n, _, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, "quic", string(buf[:n]))
		require.NoError(t, conn.SetReadDeadline(time.Time{}))

		// UDP 1000 to another address of the host goes to the kernel.
		k, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host4.Addr(), dp.PortData)))
		require.NoError(t, err)
		defer k.Close()
		_, err = c.WriteToUDPAddrPort([]byte("host"), netip.AddrPortFrom(host4.Addr(), dp.PortData))
		require.NoError(t, err)
		require.NoError(t, k.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, _, err = k.ReadFromUDPAddrPort(buf)
		require.NoError(t, err)
		assert.Equal(t, "host", string(buf[:n]))
	})
	e.stop()
	t.Run("after the stop", host)
}

// TestDeviceSharedOtherNetns opens a Shared device on a thread in another netns, as a relay in its
// own netns does. The follower and the asker must use the kernel neighbor table of that netns.
func TestDeviceSharedOtherNetns(t *testing.T) {
	e := newLink(t, 1, sharedMode)
	var r netns.NsHandle
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		// The thread stays in the new netns, so it must exit with the goroutine.
		runtime.LockOSThread()
		r, err = netns.New()
	}()
	<-done
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })

	// A move to another netns removes the addresses of the link and sets it down.
	rl, err := netlink.LinkByName("rl0")
	require.NoError(t, err)
	addrs, err := netlink.AddrList(rl, netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetNsFd(rl, int(r)))
	inNS(t, r, func() {
		for _, conf := range []string{"disable_ipv6", "accept_dad"} {
			err = errors.Join(err, os.WriteFile("/proc/sys/net/ipv6/conf/rl0/"+conf, []byte("0"), 0o644))
		}
	})
	require.NoError(t, err)
	h, err := netlink.NewHandleAt(r)
	require.NoError(t, err)
	defer h.Close()
	rl, err = h.LinkByName("rl0")
	require.NoError(t, err)
	for _, a := range addrs {
		if !a.IP.IsLinkLocalUnicast() {
			require.NoError(t, h.AddrAdd(rl, &netlink.Addr{IPNet: a.IPNet, Flags: unix.IFA_F_NODAD}))
		}
	}
	require.NoError(t, h.LinkSetUp(rl))

	opened := make(chan error, 1)
	ran := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// The thread stays in r, so it must exit with the goroutine.
		runtime.LockOSThread()
		if err := enterNetns(r); err != nil {
			opened <- err
			return
		}
		d, err := dp.OpenDevice(e.ifc, aead.GCM{})
		if err != nil {
			opened <- err
			return
		}
		e.d = d
		opened <- nil
		ran <- d.Run(ctx)
	}()
	if err := <-opened; err != nil {
		cancel()
		t.Fatalf("open the device in the other netns: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, <-ran)
	})
	for _, to := range []netip.AddrPort{netip.AddrPortFrom(peer4.Addr(), 9002), netip.AddrPortFrom(peer6.Addr(), 9002)} {
		t.Run(to.Addr().String(), func(t *testing.T) {
			c := e.listen(t, to)
			assert.True(t, e.rawArrive(t, c, to, "raw", 3*time.Second))
			_, ok := kernelEntry(t, h, to.Addr())
			assert.True(t, ok, "no kernel entry in the other netns")
		})
	}
}

// enterNetns moves the locked thread into ns, with its own sysfs (the links of ns) and bpffs, as
// "ip netns exec" does. go-afxdp reads the queues of the link in sysfs.
func enterNetns(ns netns.NsHandle) error {
	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("set the netns: %w", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare the mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make the mounts slave: %w", err)
	}
	if err := unix.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		return fmt.Errorf("mount sysfs: %w", err)
	}
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs: %w", err)
	}
	return nil
}

// TestDeviceHostXDP opens a device on a link that has an XDP program of the host. In Shared mode
// the device does not start and the program stays. In Dedicated mode the device replaces it.
func TestDeviceHostXDP(t *testing.T) {
	cases := []struct {
		mode configv1alpha1.RelayInterfaceMode
		err  string
	}{
		{mode: sharedMode, err: `the relay interface rl0 has the XDP program "host_xdp" of the host`},
		{mode: configv1alpha1.RelayInterfaceModeDedicated},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			e := newLink(t, 1, tc.mode)
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Name: "host_xdp", Type: ebpf.XDP, License: "GPL",
				Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, xdpPass), asm.Return()},
			})
			require.NoError(t, err)
			t.Cleanup(func() { prog.Close() })
			l, err := netlink.LinkByName("rl0")
			require.NoError(t, err)
			require.NoError(t, netlink.LinkSetXdpFd(l, prog.FD()))
			info, err := prog.Info()
			require.NoError(t, err)
			id, ok := info.ID()
			require.True(t, ok)
			if tc.err != "" {
				_, err := dp.OpenDevice(e.ifc, aead.GCM{})
				require.ErrorContains(t, err, tc.err)
				l, err := netlink.LinkByName("rl0")
				require.NoError(t, err)
				require.NotNil(t, l.Attrs().Xdp)
				assert.Equal(t, uint32(id), l.Attrs().Xdp.ProgId, "the program of the host is not attached")
				return
			}
			e.open(t)
			l, err = netlink.LinkByName("rl0")
			require.NoError(t, err)
			require.NotNil(t, l.Attrs().Xdp)
			assert.NotEqual(t, uint32(id), l.Attrs().Xdp.ProgId, "the program of the host is attached")
		})
	}
}
