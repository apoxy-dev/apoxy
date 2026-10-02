package vpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/agent"
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
	vpc  netip.Prefix // VPC network, with one route.

	mu      sync.Mutex
	routes  map[netip.Prefix]bool // Kernel routes that route added.
	skipped map[netip.Prefix]bool // IPv4 prefixes that wait for an own IPv4 route.
	own4    []netip.Prefix        // IPv4 routes that this host advertises.
}

// startTun makes the TUN device with its offloads, routes the VPC network to
// it, and runs the binding on it. own are the routes that this host advertises.
func startTun(ctx context.Context, fail context.CancelCauseFunc, b *psp.Binding, name string, addr netip.Addr, own []netip.Prefix) (overlay, error) {
	dev, err := wgtun.CreateTUN(name, b.DeviceMTU())
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device %s: %w", name, err)
	}
	t := &tunDev{routes: map[netip.Prefix]bool{}, skipped: map[netip.Prefix]bool{}, own4: ipv4Only(own)}
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
		t.vpc = tunnet.NetworkPrefixOf(addr)
		err = netlink.RouteAdd(&netlink.Route{LinkIndex: t.link.Attrs().Index, Dst: ipNet(t.vpc)})
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

func (t *tunDev) delAddr(addr netip.Addr) error {
	return netlink.AddrDel(t.link, &netlink.Addr{IPNet: ipNet(netip.PrefixFrom(addr, addr.BitLen()))})
}

// route adds and removes the kernel routes of the prefixes of the other
// attachments. It skips the prefixes that are not agent.Routable. It keeps the
// IPv4 prefixes until this host advertises an IPv4 route: with no such route,
// the source check of the peers drops all IPv4 packets of this host.
func (t *tunDev) route(add, remove []netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range remove {
		delete(t.skipped, p)
		if t.routes[p] {
			t.del(p)
		}
	}
	for _, p := range add {
		switch {
		case t.routes[p] || t.skipped[p] || !agent.Routable(p, t.vpc):
		case p.Addr().Is4() && len(t.own4) == 0:
			t.skip(p)
		default:
			t.add(p)
		}
	}
}

// own sets the routes that this host advertises. The first IPv4 route adds the
// skipped IPv4 prefixes. When the last one goes, the IPv4 prefixes go back to
// the skipped prefixes.
func (t *tunDev) own(routes []netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	had := len(t.own4) > 0
	t.own4 = ipv4Only(routes)
	switch has := len(t.own4) > 0; {
	case has && !had:
		for p := range t.skipped {
			delete(t.skipped, p)
			t.add(p)
		}
	case had && !has:
		for p := range t.routes {
			if p.Addr().Is4() {
				t.del(p)
				t.skip(p)
			}
		}
	}
}

// add adds the kernel route of p. t.mu must be held.
func (t *tunDev) add(p netip.Prefix) {
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: t.link.Attrs().Index, Dst: ipNet(p)}); err != nil {
		slog.Warn("Failed to add a VPC route", "prefix", p, "error", err)
		return
	}
	t.routes[p] = true
	if src, ok := t.foreignSource(p); ok {
		slog.Warn("Peers drop local traffic to an IPv4 VPC route because the source address is not in an advertised route", "prefix", p, "source", src)
	}
}

// del removes the kernel route of p. t.mu must be held.
func (t *tunDev) del(p netip.Prefix) {
	delete(t.routes, p)
	if err := netlink.RouteDel(&netlink.Route{LinkIndex: t.link.Attrs().Index, Dst: ipNet(p)}); err != nil {
		slog.Warn("Failed to remove a VPC route", "prefix", p, "error", err)
	}
}

// skip keeps the IPv4 prefix p until this host advertises an IPv4 route. t.mu
// must be held.
func (t *tunDev) skip(p netip.Prefix) {
	t.skipped[p] = true
	slog.Warn("Skipped an IPv4 VPC route because this host advertises no IPv4 route", "prefix", p)
}

// foreignSource returns the host source address of the packets to the IPv4
// prefix p on the device when that address is not in an own IPv4 route. t.mu
// must be held.
func (t *tunDev) foreignSource(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() {
		return netip.Addr{}, false
	}
	rs, err := netlink.RouteGet(p.Addr().AsSlice())
	if err != nil || len(rs) == 0 || rs[0].LinkIndex != t.link.Attrs().Index {
		return netip.Addr{}, false
	}
	src, ok := netip.AddrFromSlice(rs[0].Src)
	if !ok {
		return netip.Addr{}, false
	}
	src = src.Unmap()
	return src, !slices.ContainsFunc(t.own4, func(o netip.Prefix) bool { return o.Contains(src) })
}

// ipv4Only returns the IPv4 prefixes of routes.
func ipv4Only(routes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range routes {
		if p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
