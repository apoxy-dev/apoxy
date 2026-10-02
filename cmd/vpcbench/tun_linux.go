// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const tunName = "vpcb0"

// tunNet is the kernel network through a TUN device on the tun driver.
type tunNet struct {
	cc string
}

// startTun makes the TUN device with address self and a route to dst, and
// runs the tun driver of b on it until ctx ends. A non-empty cc sets the TCP
// congestion control of the sockets that Dial opens.
func startTun(ctx context.Context, fail context.CancelCauseFunc, b *psp.Binding, self netip.Addr, dst netip.Prefix, cc string) (overlay, error) {
	dev, err := wgtun.CreateTUN(tunName, b.DeviceMTU())
	if err != nil {
		return nil, fmt.Errorf("create TUN device %s: %w", tunName, err)
	}
	link, err := netlink.LinkByName(tunName)
	if err == nil {
		err = netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet(netip.PrefixFrom(self, self.BitLen())), Flags: unix.IFA_F_NODAD})
	}
	if err == nil {
		// The default queue of 500 packets is short for bursts.
		err = netlink.LinkSetTxQLen(link, 5000)
	}
	if err == nil {
		err = netlink.LinkSetUp(link)
	}
	if err == nil {
		err = netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipNet(dst)})
	}
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("set up TUN device %s: %w", tunName, err)
	}
	d, err := b.Tun(dev)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	go func() {
		if err := d.Run(ctx); err != nil && ctx.Err() == nil {
			fail(fmt.Errorf("tun driver failed: %w", err))
		}
	}()
	return &tunNet{cc: cc}, nil
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func (n *tunNet) Listen(a netip.AddrPort) (net.Listener, error) {
	return net.Listen("tcp", a.String())
}

func (n *tunNet) ListenUDP(a netip.AddrPort) (net.PacketConn, error) {
	return net.ListenPacket("udp", a.String())
}

func (n *tunNet) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		if n.cc == "" {
			return nil
		}
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, n.cc)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("set TCP congestion control %q: %w", n.cc, serr)
		}
		return nil
	}}
	return d.DialContext(ctx, "tcp", dst.String())
}

func (n *tunNet) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	return net.Dial("udp", dst.String())
}

// TCPCounters returns the TCP OutSegs and RetransSegs counters of this netns.
func (n *tunNet) TCPCounters() (sent, retrans uint64) {
	return uint64(max(snmpCounter("Tcp:", "OutSegs"), 0)), uint64(max(snmpCounter("Tcp:", "RetransSegs"), 0))
}

func (n *tunNet) CC() string {
	if n.cc != "" {
		return n.cc
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Close does nothing: the driver closes the device when its context ends.
func (n *tunNet) Close() {}
