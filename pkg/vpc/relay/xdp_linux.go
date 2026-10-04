// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package relay

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apoxy-dev/icx/filter"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

const (
	// xdpMaxLen is the largest IP length of a PSP datagram: the IPv6 and UDP
	// headers, the PSP overhead and the largest VPC MTU.
	xdpMaxLen = 40 + 8 + pspwire.Overhead + vpcv1alpha1.MaxMTU
	// recheckInterval is the time between two reads of the link features in
	// generic mode.
	recheckInterval = 10 * time.Second
)

// XDP forwards the PSP packets of the rows of a router in XDP.
type XDP struct {
	r     *Router
	prog  *filter.Relay
	chain func(*ebpf.Program) error
	iface string
	// joins returns the link feature that joins received UDP packets, or "".
	// It is set in generic mode, where the program would forward a joined
	// datagram as one packet.
	joins      func() (string, error)
	off        bool // The rows are out: the link joins UDP packets.
	stop, done chan struct{}
}

// StartXDP loads the XDP program of the relay and keeps its rows the same as
// the rows of r. The program forwards the PSP packets to an address of the
// link that match a row, and gives all other packets to the socket. It
// returns the attach mode: "chain", "driver" or "generic". In generic mode
// the kernel can join UDP packets before the program runs, so StartXDP fails
// when the link joins them (rx-udp-gro-forwarding or rx-gro-list is on), and
// the rows go out while the link joins them later.
func (r *Router) StartXDP(cfg XDPConfig) (*XDP, string, error) {
	ifc, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find link %s: %w", cfg.Iface, err)
	}
	addrs := cfg.Addrs
	if len(addrs) == 0 {
		if addrs, err = linkAddrs(ifc); err != nil {
			return nil, "", fmt.Errorf("failed to read the addresses of %s: %w", cfg.Iface, err)
		}
	}
	prog, err := r.newXDPProgram(cfg.Port, min(uint32(ifc.MTU), xdpMaxLen))
	if err != nil {
		return nil, "", err
	}
	if err := prog.SetAddrs(addrs); err != nil {
		_ = prog.Close()
		return nil, "", fmt.Errorf("failed to set the relay addresses: %w", err)
	}
	r.setXDP(relayTable{prog}, time.Now())
	x := &XDP{r: r, prog: prog, chain: cfg.Chain, iface: ifc.Name, stop: make(chan struct{}), done: make(chan struct{})}
	mode, generic, err := x.attach(cfg, ifc)
	if err != nil {
		r.clearXDP()
		_ = prog.Close()
		return nil, "", fmt.Errorf("failed to attach relay XDP program: %w", err)
	}
	if generic {
		x.joins = func() (string, error) { return joinsUDP(ifc.Name) }
		go x.watch()
	} else {
		close(x.done)
	}
	// The next hop lookup of XDP needs forwarding on the link.
	for _, fam := range []string{"ipv4", "ipv6"} {
		b, err := os.ReadFile(filepath.Join("/proc/sys/net", fam, "conf", cfg.Iface, "forwarding"))
		if err == nil && strings.TrimSpace(string(b)) == "0" {
			slog.Warn("Forwarding is off on the relay link; the socket path forwards these PSP packets", "iface", cfg.Iface, "family", fam)
		}
	}
	return x, mode, nil
}

// attach puts the program on the link and returns the mode, and whether the
// program runs in generic mode.
func (x *XDP) attach(cfg XDPConfig, ifc *net.Interface) (string, bool, error) {
	if cfg.Chain != nil {
		generic, err := linkXDPGeneric(ifc.Name)
		if err != nil {
			return "", false, err
		}
		if generic {
			if err := checkGRO(ifc.Name); err != nil {
				return "", false, err
			}
		}
		return "chain", generic, cfg.Chain(x.prog.Program())
	}
	if !cfg.Generic && x.prog.Attach(ifc.Index, link.XDPDriverMode) == nil {
		return "driver", false, nil
	}
	if err := checkGRO(ifc.Name); err != nil {
		return "", false, err
	}
	return "generic", true, x.prog.Attach(ifc.Index, link.XDPGenericMode)
}

// watch reads the link features each recheckInterval until Close.
func (x *XDP) watch() {
	defer close(x.done)
	t := time.NewTicker(recheckInterval)
	defer t.Stop()
	for {
		select {
		case <-x.stop:
			return
		case now := <-t.C:
			x.recheck(now)
		}
	}
}

// recheck takes the rows out while the link joins received UDP packets, and
// puts them back when it stops. The socket path forwards in between.
func (x *XDP) recheck(now time.Time) {
	k, err := x.joins()
	if err != nil {
		slog.Warn("Failed to read the features of the relay link", "iface", x.iface, "error", err)
		return
	}
	on := k != ""
	if on == x.off {
		return
	}
	x.off = on
	x.r.pauseXDP(on, now)
	if on {
		slog.Warn("The relay link joins UDP packets; the socket path forwards all PSP packets", "iface", x.iface, "feature", k)
	} else {
		slog.Info("The relay link no longer joins UDP packets; XDP forwards PSP packets again", "iface", x.iface)
	}
}

// newXDPProgram loads the XDP program with the meters of r. maxLen is the
// largest IP length of a PSP datagram.
func (r *Router) newXDPProgram(port uint16, maxLen uint32) (*filter.Relay, error) {
	rc := filter.RelayConfig{Port: port, MaxLen: maxLen}
	if r.cfg.LaneRate > 0 {
		rc.LaneRate, rc.LaneBurst = uint64(r.cfg.LaneRate), uint64(r.cfg.LaneBurst)
	}
	if r.cfg.TunnelRate > 0 {
		rc.TunnelRate, rc.TunnelBurst = uint64(r.cfg.TunnelRate), uint64(r.cfg.TunnelBurst)
	}
	return filter.NewRelay(rc)
}

// linkAddrs returns the unicast addresses of the link, without the IPv6
// link-local address. The program gets them once: the relay listens on a
// fixed address, and packets to a later address of the link take the socket
// path.
func linkAddrs(ifc *net.Interface) ([]netip.Addr, error) {
	as, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for _, a := range as {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok && !ip.IsLinkLocalUnicast() {
			addrs = append(addrs, ip.Unmap())
		}
	}
	return addrs, nil
}

// linkXDPGeneric reports whether the XDP program of the link runs in generic
// mode.
func linkXDPGeneric(name string) (bool, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return false, err
	}
	x := l.Attrs().Xdp
	if x == nil || !x.Attached {
		return false, fmt.Errorf("%s has no XDP program to run behind", name)
	}
	return x.AttachMode == nl.XDP_ATTACHED_SKB, nil
}

// joinsUDP returns the link feature that joins received UDP packets, or ""
// when the link does not join them.
func joinsUDP(name string) (string, error) {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return "", err
	}
	defer e.Close()
	f, err := e.Features(name)
	if err != nil {
		return "", fmt.Errorf("failed to read the features of %s: %w", name, err)
	}
	for _, k := range []string{"rx-udp-gro-forwarding", "rx-gro-list"} {
		if f[k] {
			return k, nil
		}
	}
	return "", nil
}

// checkGRO returns an error when the link joins received UDP packets. The
// program in generic mode would then forward a joined datagram as one packet.
func checkGRO(name string) error {
	k, err := joinsUDP(name)
	if err != nil {
		return err
	}
	if k != "" {
		return fmt.Errorf("%s is on for %s, so generic XDP gets joined UDP packets", k, name)
	}
	return nil
}

// Close takes the program out of the chain or off the link, removes all rows
// and frees the program. The socket path then forwards all packets.
func (x *XDP) Close() error {
	close(x.stop)
	<-x.done
	if x.chain != nil {
		_ = x.chain(nil)
	}
	x.r.clearXDP()
	return x.prog.Close()
}

// relayTable is the xdpTable of a filter.Relay. The program keeps time in
// CLOCK_MONOTONIC.
type relayTable struct{ p *filter.Relay }

func (t relayTable) putRow(k xdpKey, w xdpRow) error {
	return t.p.PutRow(k.src, k.spi, filter.RelayRow{Next: w.next, Tunnel: w.tunnel, Expires: filter.Monotonic() + time.Until(w.expires)})
}

func (t relayTable) deleteRow(k xdpKey) (xdpCounters, error) {
	c, err := t.p.DeleteRow(k.src, k.spi)
	return countersOf(c), err
}

func (t relayTable) counters(k xdpKey) (xdpCounters, error) {
	c, err := t.p.Counters(k.src, k.spi)
	return countersOf(c), err
}

func (t relayTable) putTunnel(id uint32) error              { return t.p.PutTunnel(id) }
func (t relayTable) deleteTunnel(id uint32) (uint64, error) { return t.p.DeleteTunnel(id) }
func (t relayTable) tunnelDrops(id uint32) (uint64, error)  { return t.p.TunnelDrops(id) }

func (t relayTable) stats() (xdpStats, error) {
	s, err := t.p.Stats()
	return xdpStats{
		packets: s.Packets, bytes: s.Bytes,
		laneDrops: s.LaneDrops, tunnelDrops: s.TunnelDrops,
		noRow: s.NoRow, expired: s.Expired, noRoute: s.NoRoute,
		malformed: s.Malformed, tooLong: s.TooLong,
	}, err
}

func countersOf(c filter.RelayCounters) xdpCounters {
	x := xdpCounters{packets: c.Packets, bytes: c.Bytes, drops: c.Drops}
	if c.Used != 0 {
		x.used = time.Now().Add(c.Used - filter.Monotonic())
	}
	return x
}

var _ xdpTable = relayTable{}
