// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// TestTooBigTun checks on a TUN device that the kernel learns the path MTU from
// the error of the binding: it refuses or fragments a larger packet.
func TestTooBigTun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a TUN device")
	}
	const devMTU, clamp = 1400, 1300
	a, b := newPairMTU(t, devMTU)
	offer(t, time.Now(), a, b)
	a.b.SetClampMTU(clamp)
	// The kernel keeps a path MTU for each destination, so each IPv4 row has its own.
	other4 := netip.MustParseAddr("10.0.0.3")
	require.NoError(t, a.b.AddRoute(netip.PrefixFrom(other4, 32), a.peer))
	ns := newTunNS(t, a, devMTU)

	cases := []struct {
		name string
		// Socket options: the level, the path MTU mode with its value, and the path MTU.
		family, level, discover, mode, mtu int
		to                                 unix.Sockaddr
		hdr                                int  // IP and UDP headers.
		fragments                          bool // The kernel fragments a large packet of the socket.
	}{
		{"IPv4 with DF", unix.AF_INET, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO, unix.IP_MTU,
			&unix.SockaddrInet4{Port: 9, Addr: b.v4.As4()}, 28, false},
		{"IPv6", unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO, unix.IPV6_MTU,
			&unix.SockaddrInet6{Port: 9, Addr: b.v6.As16()}, 48, false},
		{"IPv4 without DF", unix.AF_INET, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT, unix.IP_MTU,
			&unix.SockaddrInet4{Port: 9, Addr: other4.As4()}, 28, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fd int
			var err error
			ns.do(func() {
				if fd, err = unix.Socket(tc.family, unix.SOCK_DGRAM, 0); err != nil {
					return
				}
				if err = unix.SetsockoptInt(fd, tc.level, tc.discover, tc.mode); err == nil {
					err = unix.Connect(fd, tc.to)
				}
			})
			require.NoError(t, err)
			defer unix.Close(fd)
			pathMTU := func() int {
				mtu, err := unix.GetsockoptInt(fd, tc.level, tc.mtu)
				require.NoError(t, err)
				return mtu
			}
			require.Equal(t, devMTU, pathMTU())
			before := a.b.Stats()
			sent := func(n uint64) {
				t.Helper()
				require.Eventually(t, func() bool { return a.b.Stats().TxPackets >= before.TxPackets+n },
					5*time.Second, 5*time.Millisecond, "the binding did not send %d packets", n)
			}

			large := make([]byte, 1350-tc.hdr)
			require.NoError(t, unix.Send(fd, large, 0), "the device takes the first large packet")
			require.Eventually(t, func() bool { return pathMTU() == clamp }, 5*time.Second, 5*time.Millisecond,
				"the kernel did not take the path MTU from the error")
			// The error stays on a socket that must not fragment, until a call reads it.
			pending, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			require.NoError(t, err)

			want := uint64(1) // Packets that the binding sends after the error.
			if tc.fragments {
				assert.Zero(t, pending, "socket error")
				require.NoError(t, unix.Send(fd, large, 0))
				want = 2
			} else {
				assert.Equal(t, int(unix.EMSGSIZE), pending, "socket error")
				assert.ErrorIs(t, unix.Send(fd, large, 0), unix.EMSGSIZE)
				require.NoError(t, unix.Send(fd, make([]byte, clamp-tc.hdr), 0))
			}
			// The binding made one error, for the first packet, and dropped only that packet.
			sent(want)
			st := a.b.Stats()
			assert.Equal(t, before.TxPackets+want, st.TxPackets)
			assert.Equal(t, before.TxTooBig+1, st.TxTooBig)
			assert.Equal(t, before.TxDrops+1, st.TxDrops)
		})
	}
}

// newTunNS makes a netns with a TUN device of the binding of n, as the agent makes
// it, and runs the tun driver. The device has the addresses of n and a route to its peer.
func newTunNS(t *testing.T, n *node, mtu int) *blockNS {
	t.Helper()
	ns := &blockNS{work: make(chan func())}
	devc, errc := make(chan wgtun.Device, 1), make(chan error, 1)
	go func() {
		// The thread stays in the new netns, so it must exit with the goroutine.
		runtime.LockOSThread()
		dev, err := setupTun(n, mtu)
		if err != nil {
			errc <- err
			return
		}
		devc <- dev
		for fn := range ns.work {
			fn()
		}
	}()
	var dev wgtun.Device
	select {
	case err := <-errc:
		t.Skipf("cannot set up the test netns: %v", err)
	case dev = <-devc:
	}
	t.Cleanup(func() { close(ns.work) })
	d, err := n.b.Tun(dev)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("tun driver did not stop")
		}
	})
	return ns
}

func setupTun(n *node, mtu int) (wgtun.Device, error) {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return nil, err
	}
	dev, err := wgtun.CreateTUN("ptb0", mtu)
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName("ptb0")
	if err == nil {
		err = netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: n.v4.AsSlice(), Mask: net.CIDRMask(24, 32)}})
	}
	if err == nil {
		// No duplicate address detection, so that the address works at once.
		err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net.IPNet{IP: n.v6.AsSlice(), Mask: net.CIDRMask(64, 128)}, Flags: unix.IFA_F_NODAD,
		})
	}
	if err == nil {
		err = netlink.LinkSetUp(link)
	}
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	return dev, nil
}
