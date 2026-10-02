package vpc

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// tunAvailable tells if the process has NET_ADMIN and the host has /dev/net/tun.
func tunAvailable() bool {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil || data[0].Effective&(1<<unix.CAP_NET_ADMIN) == 0 {
		return false
	}
	_, err := os.Stat("/dev/net/tun")
	return err == nil
}

// tunDev is the kernel TUN device of the tun driver.
type tunDev struct {
	link netlink.Link
}

// startTun makes the TUN device with its offloads, routes the VPC network to
// it, and runs the binding on it.
func startTun(ctx context.Context, fail context.CancelCauseFunc, b *psp.Binding, name string, addr netip.Addr) (overlay, error) {
	dev, err := wgtun.CreateTUN(name, b.DeviceMTU())
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device %s: %w", name, err)
	}
	t := &tunDev{}
	t.link, err = netlink.LinkByName(name)
	if err == nil {
		err = t.setAddr(netip.Addr{}, addr)
	}
	if err == nil {
		// The default queue of 500 packets is short for bursts.
		err = netlink.LinkSetTxQLen(t.link, 5000)
	}
	if err == nil {
		err = netlink.LinkSetUp(t.link)
	}
	if err == nil && addr.Is6() {
		err = netlink.RouteAdd(&netlink.Route{LinkIndex: t.link.Attrs().Index, Dst: ipNet(tunnet.NetworkPrefixOf(addr))})
	}
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("failed to set up TUN device %s: %w", name, err)
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
	return t, nil
}

func (t *tunDev) setAddr(old, addr netip.Addr) error {
	if old.IsValid() {
		if err := netlink.AddrDel(t.link, &netlink.Addr{IPNet: ipNet(netip.PrefixFrom(old, old.BitLen()))}); err != nil {
			return err
		}
	}
	return netlink.AddrAdd(t.link, &netlink.Addr{IPNet: ipNet(netip.PrefixFrom(addr, addr.BitLen())), Flags: unix.IFA_F_NODAD})
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
