// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/apoxy/pkg/netns"
)

var (
	relayIP = net.IPv4(10, 99, 0, 1)
	agentIP = net.IPv4(10, 99, 0, 2)
)

// TestPathMTUNetns sends TCP between agents a and b. Agent a is in a second network
// namespace, and the relay end of its veth has a lower MTU and sends no ICMP.
func TestPathMTUNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make network namespaces")
	}
	cases := []struct {
		name      string
		linkMTU   []int // Relay end of the veth, per session of agent a.
		wantDev   int
		wantClamp int
	}{
		{"path carries the VPC MTU", []int{1500}, 1400, 0},
		{"small path at the first attach", []int{1420}, 1280, 0},
		{"path shrinks after the first attach", []int{1500, 1420}, 1400, 1280},
		{"path grows again", []int{1500, 1420, 1500}, 1400, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relayNS, agentNS := newNetns(t), newNetns(t)
			link := veth(t, relayNS, agentNS)
			w := newWorld(t)
			w.mtu = 1400
			r := w.relayOn(t, "relay-1", listenIn(t, relayNS, relayIP))
			// PSP mode, so that a QUIC fallback under load does not skip the path probe.
			b := w.agent(t, "b", r, agentOptions{udp: listenIn(t, relayNS, relayIP), tcp: true, mode: TransportPSP})
			a := w.agent(t, "a", r, agentOptions{udp: listenIn(t, agentNS, agentIP), tcp: true, mode: TransportPSP})
			var ea attachEvent
			for i, mtu := range tc.linkMTU {
				link(mtu)
				if i > 0 {
					a.reconnect()
				}
				ea = a.attached(t)
			}
			eb := b.attached(t)
			assert.Equal(t, tc.wantDev, a.binding().DeviceMTU())
			assert.Equal(t, tc.wantClamp, a.binding().ClampMTU())
			assert.Equal(t, 1400, b.binding().DeviceMTU())
			assert.Equal(t, 0, b.binding().ClampMTU())

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			echoTCP(t, a, b, ea.addr, eb.addr)
		})
	}
}

// newNetns makes a network namespace. It skips the test if it cannot.
func newNetns(t *testing.T) vnetns.NsHandle {
	t.Helper()
	type result struct {
		ns  vnetns.NsHandle
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// The thread stays locked, so it ends with the goroutine.
		runtime.LockOSThread()
		ns, err := vnetns.New()
		ch <- result{ns, err}
	}()
	res := <-ch
	if res.err != nil {
		t.Skipf("cannot make a network namespace: %v", res.err)
	}
	t.Cleanup(func() { _ = res.ns.Close() })
	return res.ns
}

// veth connects relayNS (10.99.0.1) and agentNS (10.99.0.2). The returned
// func sets the MTU of the relay end.
func veth(t *testing.T, relayNS, agentNS vnetns.NsHandle) func(mtu int) {
	t.Helper()
	rh, ah := handle(t, relayNS), handle(t, agentNS)
	require.NoError(t, rh.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "r0"}, PeerName: "a0", PeerNamespace: netlink.NsFd(agentNS),
	}))
	r0 := up(t, rh, "r0", relayIP)
	up(t, ah, "a0", agentIP)
	return func(mtu int) { require.NoError(t, rh.LinkSetMTU(r0, mtu)) }
}

func handle(t *testing.T, ns vnetns.NsHandle) *netlink.Handle {
	t.Helper()
	nl, err := netlink.NewHandleAt(ns)
	require.NoError(t, err)
	t.Cleanup(nl.Close)
	return nl
}

// up sets lo and the link up, and adds ip/24 to the link.
func up(t *testing.T, nl *netlink.Handle, name string, ip net.IP) netlink.Link {
	t.Helper()
	lo, err := nl.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, nl.LinkSetUp(lo))
	link, err := nl.LinkByName(name)
	require.NoError(t, err)
	require.NoError(t, nl.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)}}))
	require.NoError(t, nl.LinkSetUp(link))
	return link
}

// listenIn opens a UDP socket on ip in ns.
func listenIn(t *testing.T, ns vnetns.NsHandle, ip net.IP) *net.UDPConn {
	t.Helper()
	var udp *net.UDPConn
	require.NoError(t, netns.Do(ns, func() (err error) {
		udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
		return err
	}))
	return udp
}

// echoTCP sends 256 KiB from a to an echo server on b, and reads it back in 10 s.
func echoTCP(t *testing.T, a, b *testAgent, ea, eb netip.Addr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ln, err := gonet.ListenTCP(b.stack, *fullAddr(eb, 8080), ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	c, err := gonet.DialTCPWithBind(ctx, a.stack, *fullAddr(ea, 0), *fullAddr(eb, 8080), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	deadline, _ := ctx.Deadline()
	require.NoError(t, c.SetDeadline(deadline))
	want := make([]byte, 256<<10)
	_, _ = rand.Read(want)
	sent := make(chan error, 1)
	go func() {
		_, err := c.Write(want)
		sent <- err
	}()
	got := make([]byte, len(want))
	n, err := io.ReadFull(c, got)
	require.NoError(t, err, "echo stopped after %d B", n)
	require.NoError(t, <-sent)
	require.True(t, bytes.Equal(want, got), "echo data is not the same")
}
