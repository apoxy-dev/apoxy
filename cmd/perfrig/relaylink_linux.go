package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	relaydp "github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

// imdsRetry is the time between two reads of IMDS while the ENI is not attached yet.
const imdsRetry = 5 * time.Second

// relayENI finds the ENI with device index 1 in IMDS, as the relay does, and
// takes it from the OS as a production relay node does: systemd-networkd does
// not manage it, and it has no address and no route. It waits until wait ends
// for EC2 to attach the ENI. It returns the name of the link.
func relayENI(ctx context.Context, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	var ifc relaydp.Interface
	for {
		var err error
		ifc, err = relaydp.FindInterface(ctx, &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("find the ENI with device index 1: %w", err)
		}
		slog.Info("Waiting for the relay ENI", "error", err)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(imdsRetry):
		}
	}
	unit := fmt.Sprintf("[Match]\nMACAddress=%s\n\n[Link]\nUnmanaged=yes\n", ifc.MAC)
	if err := os.MkdirAll(filepath.Dir(relayNetworkFile), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(relayNetworkFile, []byte(unit), 0o644); err != nil {
		return "", err
	}
	if _, err := command(ctx, "networkctl", "reload"); err != nil {
		slog.Warn("Failed to reload systemd-networkd", "error", err)
	}
	// The OS can configure the ENI at its attach, before the reload.
	for i := range 2 {
		n, err := clearLink(ifc.Name)
		if err != nil {
			return "", err
		}
		if n > 0 {
			slog.Info("Removed the addresses and routes of the relay ENI", "dev", ifc.Name, "removed", n, "pass", i+1)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(linkSettle):
		}
	}
	slog.Info("Took the relay ENI from the OS", "dev", ifc.Name, "mac", ifc.MAC.String(), "own", ifc.Own, "gateways", ifc.Gateways)
	for _, argv := range [][]string{{"ip", "addr"}, {"ip", "route", "show", "table", "all"}, {"ip", "rule"}} {
		if out, err := command(ctx, argv...); err == nil {
			slog.Info("Network state of the relay host", "command", strings.Join(argv, " "), "output", out)
		}
	}
	return ifc.Name, nil
}

// clearLink removes the addresses that are not link-local and the routes of the
// link, and sets it up. It returns the number of addresses and routes removed.
func clearLink(dev string) (int, error) {
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return 0, err
	}
	n := 0
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return 0, fmt.Errorf("list the addresses of %s: %w", dev, err)
	}
	for _, a := range addrs {
		if a.IP.IsLinkLocalUnicast() {
			continue
		}
		if err := netlink.AddrDel(l, &a); err != nil {
			return n, fmt.Errorf("remove %s from %s: %w", a.IPNet, dev, err)
		}
		n++
	}
	// The table filter with no table gives the routes of all tables.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{LinkIndex: l.Attrs().Index},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return n, fmt.Errorf("list the routes of %s: %w", dev, err)
	}
	for _, r := range routes {
		if r.Table == unix.RT_TABLE_LOCAL || (r.Dst != nil && r.Dst.IP.IsLinkLocalUnicast()) {
			continue
		}
		if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
			return n, fmt.Errorf("remove the route %s of %s: %w", r, dev, err)
		}
		n++
	}
	return n, netlink.LinkSetUp(l)
}

// carrierDowns returns the carrier down count of dev, or 0.
func carrierDowns(dev string) int64 {
	b, err := os.ReadFile("/sys/class/net/" + dev + "/carrier_down_count")
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// bootMicros returns the time since the boot in microseconds, as /dev/kmsg has it.
func bootMicros() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e6 + uint64(ts.Nsec)/1e3
}

// readKmsg returns the kernel log lines about dev or ENA since the time since.
func readKmsg(since uint64, dev string) []string {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		slog.Warn("Failed to read the kernel log", "error", err)
		return nil
	}
	defer unix.Close(fd)
	var lines []string
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EPIPE) {
			// The kernel wrote over records that this read did not get.
			continue
		}
		if err != nil || n <= 0 {
			return lines
		}
		usec, msg, ok := kmsgLine(string(buf[:n]))
		if ok && usec >= since && kmsgMatch(msg, dev) && len(lines) < kmsgMax {
			lines = append(lines, msg)
		}
	}
}

// xdpModes are the names of the XDP attach modes of netlink.
var xdpModes = map[uint32]string{1: "driver", 2: "generic", 3: "offload", 4: "multi"}

// watchLink reads the AF_XDP sockets of dev and the mode of its XDP program each
// second until the returned function stops it. That function returns the last
// read with sockets, and the carrier changes and the kernel log of the time.
func watchLink(ctx context.Context, dev string) func() LinkRecord {
	rec := LinkRecord{Dev: dev}
	var ifindex uint32
	if ifi, err := net.InterfaceByName(dev); err == nil {
		rec.MAC, ifindex = ifi.HardwareAddr.String(), uint32(ifi.Index)
	}
	// The kernel gives the AF_XDP sockets with the xsk_diag module.
	if _, err := command(ctx, "modprobe", "xsk_diag"); err != nil {
		slog.Warn("Failed to load xsk_diag", "error", err)
	}
	since := bootMicros() - 1e6
	downs := carrierDowns(dev)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan LinkRecord, 1)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- rec
				return
			case <-t.C:
				readSockets(dev, ifindex, &rec)
			}
		}
	}()
	return func() LinkRecord {
		cancel()
		r := <-done
		r.CarrierDowns = carrierDowns(dev) - downs
		r.Kmsg = readKmsg(since, dev)
		if ifi, err := net.InterfaceByName(dev); err == nil {
			r.MTU = ifi.MTU
		}
		if e, err := ethtool.NewEthtool(); err == nil {
			if ch, err := e.GetChannels(dev); err == nil {
				r.Channels = ch.CombinedCount
			}
			e.Close()
		}
		return r
	}
}

// readSockets puts the XDP mode of dev in rec while dev has a program, and the
// AF_XDP sockets of the link ifindex while the link has sockets.
func readSockets(dev string, ifindex uint32, rec *LinkRecord) {
	if l, err := netlink.LinkByName(dev); err == nil && l.Attrs().Xdp != nil && l.Attrs().Xdp.Attached {
		rec.XDPMode = xdpModes[l.Attrs().Xdp.AttachMode]
	}
	diag, err := netlink.SocketDiagXDP()
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		rec.DiagError = err.Error()
		return
	}
	socks := make([]xskSocket, 0, len(diag))
	for _, d := range diag {
		if d.XDPInfo == nil {
			continue
		}
		s := xskSocket{ifindex: d.XDPInfo.Ifindex}
		if u := d.XDPInfo.Umem; u != nil {
			s.zeroCopy = u.Flags&netlink.XDP_DU_F_ZEROCOPY != 0
		}
		if st := d.XDPInfo.Stats; st != nil {
			s.stats = map[string]uint64{
				"rx_dropped": st.RxDropped, "rx_invalid": st.RxInvalid, "rx_full": st.RxFull,
				"fill_ring_empty": st.FillRingEmpty, "tx_invalid": st.TxInvalid, "tx_ring_empty": st.TxRingEmpty,
			}
		}
		socks = append(socks, s)
	}
	n, zc, stats := xskSummary(socks, ifindex)
	if n == 0 {
		return
	}
	rec.XSKSockets, rec.ZeroCopySockets, rec.ZeroCopy, rec.XSKStats, rec.DiagError = n, zc, zc == n, stats, ""
}
