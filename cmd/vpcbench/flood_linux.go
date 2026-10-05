// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/apoxy-dev/icx/filter"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
)

const (
	// floodMinBurst is the smallest burst of a tunnel limit, as in the relay.
	floodMinBurst = 64 << 10
	// floodRowLife is the time that the rows of the relay program live.
	floodRowLife = 24 * time.Hour
	// neighWait is the longest wait for the neighbor of a next hop.
	neighWait = 3 * time.Second
	// sendTimeout is the longest time that a send waits for room in the send
	// buffer, so that a sender sees the end of its period.
	sendTimeout = 100 * time.Millisecond
	// maxSendErrors is the number of failed sends in sequence that stops a sender.
	maxSendErrors = 1000
	// kmsgLines is the most kernel log lines of one mark.
	kmsgLines = 40
	// xdpDrop and xdpPass are the XDP actions of the counter program.
	xdpDrop = 1
	xdpPass = 2
)

// nudValid are the neighbor states with which the kernel sends to a neighbor.
const nudValid = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT | netlink.NUD_NOARP

// sysCounters are the counters of /sys/class/net/DEV/statistics in a mark.
var sysCounters = []string{"rx_packets", "tx_packets", "rx_dropped", "tx_dropped", "rx_over_errors", "rx_missed_errors", "rx_errors"}

// floodHostState reads the counters of a flood host and of its link.
type floodHostState struct {
	start time.Time
	dev   string
	irq   *bench.IRQTimer // Nil when the host cannot load BPF programs.
	kmsg  int             // The kernel log, or -1.
	// words are the name of the link and the prefix of the log lines of its driver.
	words []string
}

// newFloodHostState starts the IRQ timer of the host of the link dev.
func newFloodHostState(start time.Time, dev string) *floodHostState {
	h := &floodHostState{start: start, dev: dev, kmsg: openKmsg(), words: []string{dev}}
	if d := linkOf(dev).Driver; d != "" {
		h.words = append(h.words, d+" ")
	}
	irq, err := bench.NewIRQTimer()
	if err != nil {
		slog.Warn("Failed to start the IRQ timer; the result has no IRQ time", "error", err)
		return h
	}
	h.irq = irq
	return h
}

func (h *floodHostState) close() {
	h.irq.Close()
	if h.kmsg >= 0 {
		_ = unix.Close(h.kmsg)
	}
}

// openKmsg opens the kernel log at its end, or returns -1.
func openKmsg() int {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1
	}
	if _, err := unix.Seek(fd, 0, unix.SEEK_END); err != nil {
		_ = unix.Close(fd)
		return -1
	}
	return fd
}

// readKmsg returns the new records of the kernel log fd that have one of the
// words, at most kmsgLines. A driver logs there why it reset its link.
func readKmsg(fd int, words ...string) []string {
	if fd < 0 {
		return nil
	}
	var out []string
	b := make([]byte, 8192)
	// The limit ends the loop when the kernel logs faster than the loop reads.
	for range 100000 {
		n, err := unix.Read(fd, b)
		if err == unix.EPIPE {
			// The kernel wrote over records that the loop did not read.
			continue
		}
		if err != nil || n <= 0 {
			break
		}
		text := kmsgText(string(b[:n]))
		for _, w := range words {
			if w != "" && strings.Contains(text, w) && len(out) < kmsgLines {
				out = append(out, text)
				break
			}
		}
	}
	return out
}

// mark reads the counters of the host.
func (h *floodHostState) mark() *floodMark {
	m := &floodMark{Nanos: time.Since(h.start).Nanoseconds(), NIC: map[string]uint64{}, CPUs: bench.PerCPU()}
	if e, err := ethtool.NewEthtool(); err == nil {
		if stats, err := e.Stats(h.dev); err == nil {
			m.NIC = stats
		}
		e.Close()
	}
	for _, name := range sysCounters {
		b, err := os.ReadFile(filepath.Join("/sys/class/net", h.dev, "statistics", name))
		if err != nil {
			continue
		}
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
			m.NIC["sys_"+name] = v
		}
	}
	if b, err := os.ReadFile(filepath.Join("/sys/class/net", h.dev, "carrier_down_count")); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
			m.NIC["sys_carrier_down"] = v
		}
	}
	m.Kmsg = readKmsg(h.kmsg, h.words...)
	if b, err := os.ReadFile("/proc/net/snmp"); err == nil {
		m.SNMP = snmpCounters(string(b))
	}
	var err error
	if m.IRQ, m.NetRX, err = h.irq.Nanos(); err != nil {
		slog.Warn("Failed to read the IRQ timer", "error", err)
	}
	return m
}

// linkOf returns the settings of the link dev.
func linkOf(dev string) *floodLink {
	l := &floodLink{Dev: dev}
	if ifc, err := net.InterfaceByName(dev); err == nil {
		l.MTU = ifc.MTU
	}
	e, err := ethtool.NewEthtool()
	if err != nil {
		return l
	}
	defer e.Close()
	l.Driver, _ = e.DriverName(dev)
	if ch, err := e.GetChannels(dev); err == nil {
		l.Channels = ch.CombinedCount
	}
	if r, err := e.GetRing(dev); err == nil {
		l.RxRing, l.TxRing = r.RxPending, r.TxPending
	}
	return l
}

// devOf returns the link that has the address a.
func devOf(a netip.Addr) (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, x := range addrs {
			if n, ok := x.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == a {
					return ifc.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no link has the address %s", a)
}

// pinNeighbor makes the neighbor of the route to dst permanent until the returned
// function runs: a host with a full RX queue can drop the answers to ARP probes.
// resolve, if set, sends a packet to dst when the kernel does not know the neighbor.
func pinNeighbor(dst netip.Addr, resolve func()) (func(), error) {
	routes, err := netlink.RouteGet(dst.AsSlice())
	if err != nil || len(routes) == 0 {
		return nil, fmt.Errorf("no route to %s: %w", dst, err)
	}
	// A loopback link has no neighbors.
	if l, err := netlink.LinkByIndex(routes[0].LinkIndex); err == nil && l.Attrs().Flags&net.FlagLoopback != 0 {
		return func() {}, nil
	}
	ip := net.IP(dst.AsSlice())
	if gw := routes[0].Gw; len(gw) > 0 {
		ip = gw
	}
	fam := netlink.FAMILY_V4
	if ip.To4() == nil {
		fam = netlink.FAMILY_V6
	}
	deadline := time.Now().Add(neighWait)
	for {
		neighs, err := netlink.NeighList(routes[0].LinkIndex, fam)
		if err != nil {
			return nil, err
		}
		for _, n := range neighs {
			if !n.IP.Equal(ip) || len(n.HardwareAddr) == 0 || n.State&nudValid == 0 {
				continue
			}
			if n.State&(netlink.NUD_PERMANENT|netlink.NUD_NOARP) != 0 {
				return func() {}, nil
			}
			pin := &netlink.Neigh{LinkIndex: n.LinkIndex, Family: fam, State: netlink.NUD_PERMANENT, IP: ip, HardwareAddr: n.HardwareAddr}
			if err := netlink.NeighSet(pin); err != nil {
				return nil, fmt.Errorf("make the neighbor %s permanent: %w", ip, err)
			}
			return func() {
				pin.State = netlink.NUD_STALE
				if err := netlink.NeighSet(pin); err != nil {
					slog.Warn("Failed to set the neighbor back", "neighbor", ip.String(), "error", err)
				}
			}, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the kernel has no neighbor %s for %s", ip, dst)
		}
		if resolve != nil {
			resolve()
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// mmsghdr is struct mmsghdr of sendmmsg.
type mmsghdr struct {
	hdr unix.Msghdr
	n   uint32
}

// floodSock is the socket of one source port. All its messages have the same bytes.
type floodSock struct {
	fd   int
	iov  unix.Iovec
	hdrs []mmsghdr
}

// floodSender sends the packets of all source ports.
type floodSender struct {
	dev   string
	segs  int // Packets of one message.
	run   floodRun
	socks []*floodSock
	host  *floodHostState
	unpin func()
}

// newFloodSender opens one connected socket for each source port of run, from
// the address local to dst(i).
func newFloodSender(local netip.Addr, dst func(i int) netip.AddrPort, run floodRun, sndbuf int) (*floodSender, error) {
	dev, err := devOf(local)
	if err != nil {
		return nil, err
	}
	s := &floodSender{dev: dev, segs: run.GSO, run: run, unpin: func() {}}
	for i := range run.Ports {
		fd, err := floodSocket(netip.AddrPortFrom(local, uint16(floodFirstPort+i)), dst(i), sndbuf)
		if err != nil {
			s.close()
			return nil, fmt.Errorf("socket of source port %d: %w", floodFirstPort+i, err)
		}
		s.socks = append(s.socks, &floodSock{fd: fd})
	}
	if err := s.setSegs(s.segs); err != nil {
		s.close()
		return nil, err
	}
	// A link with no checksum offload refuses a GSO message.
	if s.segs > 1 {
		if err := s.socks[0].sendOne(); errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EIO) {
			slog.Warn("The link refused a UDP GSO message; each message is one packet", "link", dev, "error", err)
			if err := s.setSegs(1); err != nil {
				s.close()
				return nil, err
			}
		}
	}
	unpin, err := pinNeighbor(dst(0).Addr(), nil)
	if err != nil {
		slog.Warn("Failed to make the neighbor of the destination permanent", "error", err)
	} else {
		s.unpin = unpin
	}
	s.host = newFloodHostState(time.Now(), dev)
	return s, nil
}

// floodSocket opens a UDP socket from src that is connected to dst.
func floodSocket(src, dst netip.AddrPort, sndbuf int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	tv := unix.NsecToTimeval(sendTimeout.Nanoseconds())
	err = errors.Join(
		unix.Bind(fd, &unix.SockaddrInet4{Port: int(src.Port()), Addr: src.Addr().As4()}),
		unix.Connect(fd, &unix.SockaddrInet4{Port: int(dst.Port()), Addr: dst.Addr().As4()}),
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv),
	)
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if sndbuf > 0 {
		// The forced size is not under the limit of net.core.wmem_max. It needs root.
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sndbuf) != nil {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, sndbuf)
		}
	}
	return fd, nil
}

// setSegs makes each message of each socket segs packets, with run.Batch
// messages for each call. The sockets of one sender have the same bytes.
func (s *floodSender) setSegs(segs int) error {
	s.segs = segs
	seg := s.run.Size - ipv4Len - udpLen
	bufs := map[uint32][]byte{}
	for i, k := range s.socks {
		// 0 turns the segments off.
		size := 0
		if segs > 1 {
			size = seg
		}
		if err := unix.SetsockoptInt(k.fd, unix.SOL_UDP, unix.UDP_SEGMENT, size); err != nil && segs > 1 {
			return fmt.Errorf("set the UDP GSO size: %w", err)
		}
		_, spi := senderOf(i)
		if bufs[spi] == nil {
			bufs[spi] = floodPayload(s.run.Size, segs, spi)
		}
		buf := bufs[spi]
		k.iov = unix.Iovec{Base: &buf[0]}
		k.iov.SetLen(len(buf))
		k.hdrs = make([]mmsghdr, s.run.Batch)
		for j := range k.hdrs {
			k.hdrs[j].hdr.Iov = &k.iov
			k.hdrs[j].hdr.SetIovlen(1)
		}
	}
	return nil
}

// sendmmsg sends the first n messages of k and returns the messages that the
// kernel took.
func (k *floodSock) sendmmsg(n int) (int, unix.Errno) {
	r, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(k.fd), uintptr(unsafe.Pointer(&k.hdrs[0])), uintptr(n), 0, 0, 0)
	return int(r), errno
}

// sendOne sends one message of k.
func (k *floodSock) sendOne() error {
	if _, errno := k.sendmmsg(1); errno != 0 {
		return errno
	}
	return nil
}

// loop sends on k until stop is set, on its own thread. interval is the time between
// two calls, or 0 for no limit, and first is the time of the first call.
func (k *floodSock) loop(stop *atomic.Bool, interval time.Duration, first time.Time) (msgs, errs uint64) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	next := first
	for interval > 0 && !stop.Load() && time.Until(next) > 0 {
		time.Sleep(min(time.Until(next), time.Millisecond))
	}
	fails := 0
	for !stop.Load() {
		n, errno := k.sendmmsg(len(k.hdrs))
		switch {
		case errno == unix.EAGAIN || errno == unix.EINTR:
			continue
		case errno != 0:
			errs++
			if fails++; fails >= maxSendErrors {
				return msgs, errs
			}
			continue
		}
		fails = 0
		msgs += uint64(n)
		if interval <= 0 {
			continue
		}
		next = next.Add(interval)
		for !stop.Load() {
			d := time.Until(next)
			if d <= 0 {
				break
			}
			// A sleep is not exact, so the thread spins for the last part.
			if d > 200*time.Microsecond {
				time.Sleep(d - 100*time.Microsecond)
			}
		}
		// After a stall, the sender does not send the lost packets in one burst.
		if time.Since(next) > 100*interval {
			next = time.Now()
		}
	}
	return msgs, errs
}

// send sends on all ports for the time d, with one thread for each port.
func (s *floodSender) send(ctx context.Context, d time.Duration) (floodSent, error) {
	var interval time.Duration
	if s.run.TargetPPS > 0 {
		perCall := float64(s.run.Batch * s.segs)
		interval = time.Duration(perCall * float64(s.run.Ports) / s.run.TargetPPS * float64(time.Second))
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	msgs, errs := make([]uint64, len(s.socks)), make([]uint64, len(s.socks))
	begin := time.Now()
	for i, k := range s.socks {
		// The ports send at different times of the interval, so that the link gets no bursts.
		first := begin.Add(interval * time.Duration(i) / time.Duration(len(s.socks)))
		wg.Go(func() { msgs[i], errs[i] = k.loop(&stop, interval, first) })
	}
	err := bench.Sleep(ctx, d, nil)
	stop.Store(true)
	wg.Wait()
	out := floodSent{seconds: time.Since(begin).Seconds(), packets: make([]uint64, len(msgs))}
	var total uint64
	for i, n := range msgs {
		out.packets[i] = n * uint64(s.segs)
		out.errors += errs[i]
		total += n
	}
	if err == nil && total == 0 {
		err = fmt.Errorf("the kernel took no message (%d failed sends)", out.errors)
	}
	return out, err
}

// mark reads the counters of the source host.
func (s *floodSender) mark(start time.Time) *floodMark {
	m := s.host.mark()
	m.Nanos = time.Since(start).Nanoseconds()
	m.Link = linkOf(s.dev)
	return m
}

func (s *floodSender) close() {
	s.unpin()
	if s.host != nil {
		s.host.close()
	}
	for _, k := range s.socks {
		_ = unix.Close(k.fd)
	}
}

// linkAddrs returns the unicast addresses of the link, without the IPv6
// link-local address, as the relay gives them to its program.
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

// checkGRO returns an error when the link joins received UDP packets, as the
// relay does. The program in generic mode would forward a joined datagram as one packet.
func checkGRO(name string) error {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	defer e.Close()
	f, err := e.Features(name)
	if err != nil {
		return fmt.Errorf("read the features of %s: %w", name, err)
	}
	for _, k := range []string{"rx-udp-gro-forwarding", "rx-gro-list"} {
		if f[k] {
			return fmt.Errorf("%s is on for %s, so generic XDP gets joined UDP packets", k, name)
		}
	}
	return nil
}

// floodRelayConfig returns the config of the relay program for a link with the MTU
// mtu and the driver driver. It is the config of the relay of the product.
func floodRelayConfig(o floodOptions, port uint16, mtu int, driver string) filter.RelayConfig {
	cfg := filter.RelayConfig{
		Port: port, MaxLen: min(uint32(mtu), floodMaxLen), NextHopCache: o.XDPHop,
		// ena tells its device of each XDP_TX packet, so the program sends with a redirect.
		Redirect: driver == "ena",
	}
	if o.TunnelRate > 0 {
		cfg.TunnelRate = uint64(o.TunnelRate / 8)
		cfg.TunnelBurst = max(cfg.TunnelRate/10, floodMinBurst)
	}
	return cfg
}

// floodXDP is the relay program on a link.
type floodXDP struct {
	prog   *filter.Relay
	geneve *filter.Program // The Geneve program in the mode chain.
	flags  int             // The attach flags of icx before the mode chain.
	ifc    *net.Interface
	link   *floodLink
}

// startFloodXDP loads the relay program for the UDP address listen and puts it
// on the link of o in the mode of o.
func startFloodXDP(o floodOptions, listen netip.AddrPort) (*floodXDP, error) {
	ifc, err := net.InterfaceByName(o.XDP)
	if err != nil {
		return nil, fmt.Errorf("find the link %s: %w", o.XDP, err)
	}
	addrs, err := linkAddrs(ifc)
	if err != nil {
		return nil, err
	}
	info := linkOf(ifc.Name)
	cfg := floodRelayConfig(o, listen.Port(), ifc.MTU, info.Driver)
	info.MaxLen, info.Redirect = cfg.MaxLen, cfg.Redirect
	prog, err := filter.NewRelay(cfg)
	if err != nil {
		return nil, err
	}
	x := &floodXDP{prog: prog, ifc: ifc, link: info}
	if err := prog.SetAddrs(addrs); err != nil {
		_ = x.close()
		return nil, fmt.Errorf("set the relay addresses: %w", err)
	}
	if info.XDPMode, err = x.attach(o.XDPMode, listen); err != nil {
		_ = x.close()
		return nil, fmt.Errorf("attach the relay program to %s: %w", ifc.Name, err)
	}
	if b, err := os.ReadFile(filepath.Join("/proc/sys/net/ipv4/conf", ifc.Name, "forwarding")); err == nil && strings.TrimSpace(string(b)) == "0" {
		slog.Warn("Forwarding is off on the relay link; the program forwards no packet", "iface", ifc.Name)
	}
	return x, nil
}

// attach puts the program on the link and returns the mode: driver, generic or chain.
func (x *floodXDP) attach(mode string, listen netip.AddrPort) (string, error) {
	name := x.ifc.Name
	if mode == "driver" {
		err := x.prog.Attach(x.ifc.Index, link.XDPDriverMode)
		if err == nil {
			return "driver", nil
		}
		slog.Warn("The driver of the relay link refused the XDP program; trying generic mode", "iface", name, "error", err)
		mode = "generic"
	}
	if err := checkGRO(name); err != nil {
		return "", err
	}
	if mode == "generic" {
		return "generic", x.prog.Attach(x.ifc.Index, link.XDPGenericMode)
	}
	// As in the product, the Geneve program has the UDP port of the relay and runs in
	// generic mode. It passes the PSP packets, which are not Geneve, to the relay program.
	g, err := filter.Geneve(net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return "", err
	}
	x.geneve = g
	// The detach must have the flags of the attach, so they stay until close.
	x.flags, filter.AttachFlags = filter.AttachFlags, unix.XDP_FLAGS_SKB_MODE
	if err := g.Attach(x.ifc.Index); err != nil {
		return "", err
	}
	return "chain", g.Chain(x.prog.Program())
}

// putRows puts one row for each source port of h at the address from.
func (x *floodXDP) putRows(o floodOptions, from netip.Addr, h *floodHello) (netip.Addr, error) {
	next, err := netip.ParseAddr(h.Next)
	if err != nil {
		return next, fmt.Errorf("next hop of the hello: %w", err)
	}
	if h.Ports < 1 || h.NextPorts < 1 || h.FirstPort < 1 || h.FirstPort+h.Ports > 1<<16 || h.FirstNext < 1 || h.FirstNext+h.NextPorts > 1<<16 {
		return next, fmt.Errorf("bad ports in the hello: %+v", *h)
	}
	expires := filter.Monotonic() + floodRowLife
	for i := range h.Ports {
		sender, spi := senderOf(i)
		row := filter.RelayRow{Next: netip.AddrPortFrom(next, uint16(h.FirstNext+i%h.NextPorts)), Expires: expires}
		if o.TunnelRate > 0 {
			// The ports of one sender have one tunnel limit, as one agent session has.
			row.Tunnel = uint32(sender) + 1
			if i%floodLanes == 0 {
				if err := x.prog.PutTunnel(row.Tunnel); err != nil {
					return next, err
				}
			}
		}
		if err := x.prog.PutRow(netip.AddrPortFrom(from, uint16(h.FirstPort+i)), spi, row); err != nil {
			return next, fmt.Errorf("put the row of source port %d: %w", h.FirstPort+i, err)
		}
	}
	return next, nil
}

// rows returns the packets that the program forwarded for each source port of h.
func (x *floodXDP) rows(from netip.Addr, h *floodHello) []uint64 {
	out := make([]uint64, h.Ports)
	for i := range out {
		_, spi := senderOf(i)
		if c, err := x.prog.Counters(netip.AddrPortFrom(from, uint16(h.FirstPort+i)), spi); err == nil {
			out[i] = c.Packets
		}
	}
	return out
}

func (x *floodXDP) close() error {
	var errs []error
	if x.geneve != nil {
		errs = append(errs, x.geneve.Chain(nil), x.geneve.Detach(x.ifc.Index), x.geneve.Close())
		filter.AttachFlags = x.flags
	}
	return errors.Join(append(errs, x.prog.Close())...)
}

// clearXDP takes an XDP program that a stopped process left off the link.
func clearXDP(name string) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return
	}
	x := l.Attrs().Xdp
	if x == nil || !x.Attached {
		return
	}
	for _, flags := range []int{unix.XDP_FLAGS_SKB_MODE, unix.XDP_FLAGS_DRV_MODE} {
		_ = netlink.LinkSetXdpFdWithFlags(l, -1, flags)
	}
	slog.Warn("Removed an old XDP program from the link", "iface", name, "prog_id", x.ProgId)
}

// runFloodRelay runs the relay program with the rows of the source until the
// source stops it or disconnects, or ctx ends.
func runFloodRelay(ctx context.Context, o floodOptions, ready func(netip.AddrPort)) error {
	start := time.Now()
	ua, err := net.ResolveUDPAddr("udp4", o.Listen)
	if err != nil {
		return err
	}
	// The socket gets the packets that the program passes, so the kernel sends no
	// ICMP error for them.
	uc, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return err
	}
	defer uc.Close()
	addr := uc.LocalAddr().(*net.UDPAddr).AddrPort()
	// A driver can stop the link when it gets the XDP program, so the control port opens first.
	cl, err := net.Listen("tcp4", addr.String())
	if err != nil {
		return err
	}
	defer cl.Close()
	var sock atomic.Uint64
	go func() {
		b := make([]byte, 1<<16)
		for {
			if _, _, err := uc.ReadFromUDPAddrPort(b); err != nil {
				return
			}
			sock.Add(1)
		}
	}()

	clearXDP(o.XDP)
	x, err := startFloodXDP(o, addr)
	if err != nil {
		return err
	}
	defer x.close()
	xdpCPU := func() float64 { return 0 }
	if o.XDPStats {
		sec, stop, err := xdpSeconds(o.XDP)
		if err != nil {
			return fmt.Errorf("read the XDP run time: %w", err)
		}
		defer stop()
		xdpCPU = sec
	}
	host := newFloodHostState(start, o.XDP)
	defer host.close()
	slog.Info("Relay forwards PSP packets in XDP", "id", o.ID, "address", addr, "iface", o.XDP, "mode", x.link.XDPMode,
		"driver", x.link.Driver, "mtu", x.link.MTU, "channels", x.link.Channels, "max_len", x.link.MaxLen, "redirect", x.link.Redirect)
	if ready != nil {
		ready(addr)
	}

	var hello *floodHello
	var from netip.Addr
	unpin := func() {}
	defer func() { unpin() }()
	return floodPeer(ctx, cl, o.ID, o.Seq, o.StartTimeout, func(req request, remote netip.Addr) (reply, error) {
		switch req.Op {
		case "hello":
			next, err := x.putRows(o, remote, req.Flood)
			if err != nil {
				return reply{}, err
			}
			hello, from = req.Flood, remote
			// The program needs the neighbor of the next hop. A datagram to the counter
			// makes the kernel look for it; the counter program drops the datagram.
			probe := netip.AddrPortFrom(next, uint16(req.Flood.FirstNext))
			u, err := pinNeighbor(next, func() { _, _ = uc.WriteToUDPAddrPort([]byte{0}, probe) })
			if err != nil {
				return reply{}, err
			}
			unpin()
			unpin = u
			slog.Info("Put the rows of the source", "source", remote, "ports", req.Flood.Ports, "next", next, "next_ports", req.Flood.NextPorts)
			return reply{Flood: &floodMark{Link: x.link}}, nil
		case "mark":
			if hello == nil {
				return reply{}, errors.New("mark before hello")
			}
			st, err := x.prog.Stats()
			if err != nil {
				return reply{}, err
			}
			m := host.mark()
			m.Link = x.link
			m.XDP = &relayXDPStats{
				Packets: st.Packets, Bytes: st.Bytes, LaneDrops: st.LaneDrops, TunnelDrops: st.TunnelDrops,
				NoRow: st.NoRow, Expired: st.Expired, NoRoute: st.NoRoute, Malformed: st.Malformed, TooLong: st.TooLong,
			}
			m.XDPSeconds, m.Rows, m.SockPkts = xdpCPU(), x.rows(from, hello), sock.Load()
			o.marked(req.Index, req.Window)
			return reply{Flood: m}, nil
		}
		return reply{}, fmt.Errorf("unknown op %q", req.Op)
	})
}

// portCount is the packets and the frame bytes of one UDP port of the counter.
type portCount struct{ Packets, Bytes uint64 }

// portCounter is an XDP program that counts and drops the IPv4 UDP packets to
// the ports of the counter. It passes all other packets.
type portCounter struct {
	counts *ebpf.Map
	prog   *ebpf.Program
	link   link.Link
}

// newPortCounter loads the program for the ports first to first+n-1.
func newPortCounter(first, n int) (*portCounter, error) {
	counts, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 16, MaxEntries: uint32(n)})
	if err != nil {
		return nil, err
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, Instructions: countProg(counts, first, n), License: "GPL"})
	if err != nil {
		_ = counts.Close()
		return nil, fmt.Errorf("load the counter program: %w", err)
	}
	return &portCounter{counts: counts, prog: prog}, nil
}

// countProg returns the instructions of the counter program.
func countProg(counts *ebpf.Map, first, n int) asm.Instructions {
	const udpAt = ethLen + ipv4Len
	return asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.Word), // data
		asm.LoadMem(asm.R7, asm.R1, 4, asm.Word), // data_end
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.Add.Imm(asm.R2, udpAt+udpLen),
		asm.JGT.Reg(asm.R2, asm.R7, "pass"),
		// IPv4 with a header of 20 bytes, and UDP.
		asm.LoadMem(asm.R2, asm.R6, 12, asm.Half),
		asm.HostTo(asm.BE, asm.R2, asm.Half),
		asm.JNE.Imm(asm.R2, unix.ETH_P_IP, "pass"),
		asm.LoadMem(asm.R2, asm.R6, ethLen, asm.Byte),
		asm.JNE.Imm(asm.R2, 0x45, "pass"),
		asm.LoadMem(asm.R2, asm.R6, ethLen+9, asm.Byte),
		asm.JNE.Imm(asm.R2, unix.IPPROTO_UDP, "pass"),
		// The key is the place of the destination port in the ports of the counter.
		asm.LoadMem(asm.R2, asm.R6, udpAt+2, asm.Half),
		asm.HostTo(asm.BE, asm.R2, asm.Half),
		asm.Sub.Imm(asm.R2, int32(first)),
		asm.JGE.Imm(asm.R2, int32(n), "pass"),
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),
		// The frame bytes are the IP length and the Ethernet header.
		asm.LoadMem(asm.R8, asm.R6, ethLen+2, asm.Half),
		asm.HostTo(asm.BE, asm.R8, asm.Half),
		asm.Add.Imm(asm.R8, ethLen),
		asm.LoadMapPtr(asm.R1, counts.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord),
		asm.Add.Reg(asm.R1, asm.R8),
		asm.StoreMem(asm.R0, 8, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, xdpDrop),
		asm.Return(),
		asm.Mov.Imm(asm.R0, xdpPass).WithSymbol("pass"),
		asm.Return(),
	}
}

// attach puts the program on the link in the mode driver or generic, and
// returns the mode that the link took.
func (c *portCounter) attach(ifindex int, mode string) (string, error) {
	if mode == "driver" {
		l, err := link.AttachXDP(link.XDPOptions{Program: c.prog, Interface: ifindex, Flags: link.XDPDriverMode})
		if err == nil {
			c.link = l
			return "driver", nil
		}
		slog.Warn("The driver of the counter link refused the XDP program; trying generic mode", "error", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: c.prog, Interface: ifindex, Flags: link.XDPGenericMode})
	if err != nil {
		return "", err
	}
	c.link = l
	return "generic", nil
}

// read returns the packets and the frame bytes of each port.
func (c *portCounter) read() (pkts, bytes []uint64, err error) {
	n := int(c.counts.MaxEntries())
	pkts, bytes = make([]uint64, n), make([]uint64, n)
	var cpus []portCount
	for i := range n {
		if err := c.counts.Lookup(uint32(i), &cpus); err != nil {
			return nil, nil, err
		}
		for _, v := range cpus {
			pkts[i] += v.Packets
			bytes[i] += v.Bytes
		}
	}
	return pkts, bytes, nil
}

func (c *portCounter) close() {
	if c.link != nil {
		_ = c.link.Close()
	}
	_ = c.prog.Close()
	_ = c.counts.Close()
}

// runFloodCounter counts the packets to its UDP ports in XDP until the source
// disconnects or ctx ends.
func runFloodCounter(ctx context.Context, o floodOptions, ready func(netip.AddrPort)) error {
	start := time.Now()
	// A driver can stop the link when it gets the XDP program, so the control port opens first.
	cl, err := net.Listen("tcp4", o.Listen)
	if err != nil {
		return err
	}
	defer cl.Close()
	ifc, err := net.InterfaceByName(o.XDP)
	if err != nil {
		return fmt.Errorf("find the link %s: %w", o.XDP, err)
	}
	clearXDP(o.XDP)
	c, err := newPortCounter(floodFirstNext, floodMaxNext)
	if err != nil {
		return err
	}
	defer c.close()
	info := linkOf(ifc.Name)
	if info.XDPMode, err = c.attach(ifc.Index, o.XDPMode); err != nil {
		return fmt.Errorf("attach the counter program to %s: %w", ifc.Name, err)
	}
	host := newFloodHostState(start, o.XDP)
	defer host.close()
	slog.Info("Counter drops and counts UDP packets in XDP", "id", o.ID, "iface", o.XDP, "mode", info.XDPMode, "driver", info.Driver,
		"mtu", info.MTU, "channels", info.Channels, "first_port", floodFirstNext, "ports", floodMaxNext)
	if ready != nil {
		ready(cl.Addr().(*net.TCPAddr).AddrPort())
	}
	return floodPeer(ctx, cl, o.ID, o.Seq, o.StartTimeout, func(req request, _ netip.Addr) (reply, error) {
		switch req.Op {
		case "hello":
			return reply{Flood: &floodMark{Link: info}}, nil
		case "mark":
			m := host.mark()
			m.Link = info
			var err error
			if m.PortPkts, m.PortBytes, err = c.read(); err != nil {
				return reply{}, err
			}
			o.marked(req.Index, req.Window)
			return reply{Flood: m}, nil
		}
		return reply{}, fmt.Errorf("unknown op %q", req.Op)
	})
}
