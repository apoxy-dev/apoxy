package netstack

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"

	"github.com/dpeckett/network"
	"github.com/prometheus/client_golang/prometheus"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const IPv6MinMTU = 1280 // IPv6 minimum MTU, required for some PPPoE links.

// TunnelMTU is the MTU used for tunnel TUN devices. Sized to fit in a single
// QUIC datagram after PMTUD on a typical 1500-byte internet path:
// 1500 (Ethernet) - 20 (IP) - 8 (UDP) - ~26 (QUIC framing) - 1 (contextID) ≈ 1445.
// We use 1420 to leave headroom for path variance.
const TunnelMTU = 1420

var _ tun.Device = (*TunDevice)(nil)

type TunDevice struct {
	ns             *Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	// done is closed by Close. incomingPacket is never closed, so a send can not panic.
	done   chan struct{}
	mtu    int
	closed atomic.Bool
}

func NewTunDevice(pcapPath string) (*TunDevice, error) {
	ns, err := NewStack(TunnelMTU, pcapPath)
	if err != nil {
		return nil, err
	}
	tunDev := &TunDevice{
		ns:             ns,
		events:         make(chan tun.Event, 1),
		incomingPacket: make(chan *buffer.View, 1024),
		done:           make(chan struct{}),
		mtu:            int(ns.Endpoint.MTU()),
	}
	ns.Endpoint.AddNotify(tunDev)
	tunDev.events <- tun.EventUp

	return tunDev, nil
}

func (tun *TunDevice) AddAddr(addr netip.Prefix) error {
	return tun.ns.AddAddr(addr)
}

func (tun *TunDevice) DelAddr(addr netip.Prefix) error {
	return tun.ns.DelAddr(addr)
}

func (tun *TunDevice) Name() (string, error) { return "go", nil }

func (tun *TunDevice) File() *os.File { return nil }

func (tun *TunDevice) Events() <-chan tun.Event { return tun.events }

func (tun *TunDevice) MTU() (int, error) { return tun.mtu, nil }

func (tun *TunDevice) BatchSize() int { return 1 }

func (tun *TunDevice) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	if tun.closed.Load() {
		return 0, os.ErrClosed
	}

	var view *buffer.View
	select {
	case view = <-tun.incomingPacket:
	case <-tun.done:
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (tun *TunDevice) Write(buf [][]byte, offset int) (int, error) {
	if tun.closed.Load() {
		return 0, os.ErrClosed
	}

	for _, buf := range buf {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		defer pkb.DecRef()

		switch packet[0] >> 4 {
		case 4:
			tun.ns.Endpoint.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ns.Endpoint.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

func (tun *TunDevice) WriteNotify() {
	if tun.closed.Load() {
		return
	}

	pkt := tun.ns.Endpoint.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	select {
	case tun.incomingPacket <- view:
	case <-tun.done:
		view.Release()
	}
}

func (tun *TunDevice) Close() error {
	if tun.closed.Swap(true) {
		return nil
	}

	// Stop a blocked WriteNotify first. It can hold stack locks that the stack close needs.
	close(tun.done)
	tun.ns.Close()

	if tun.events != nil {
		close(tun.events)
	}

	return nil
}

// Network returns the network abstraction for the TUN device.
func (tun *TunDevice) Network(resolveConf *network.ResolveConfig) *network.NetstackNetwork {
	return tun.ns.Network(resolveConf)
}

// LocalAddresses returns the list of local addresses assigned to the TUN device.
func (tun *TunDevice) LocalAddresses() ([]netip.Prefix, error) {
	nic := tun.ns.Stack.NICInfo()[tun.ns.NICID]

	var addrs []netip.Prefix
	for _, assignedAddr := range nic.ProtocolAddresses {
		addrs = append(addrs, netip.PrefixFrom(
			addrFromNetstackIP(assignedAddr.AddressWithPrefix.Address),
			assignedAddr.AddressWithPrefix.PrefixLen,
		))
	}

	return addrs, nil
}

// ListenPacket creates an unconnected UDP PacketConn bound to the given
// overlay address inside the gvisor network stack.
func (tun *TunDevice) ListenPacket(addr netip.AddrPort) (net.PacketConn, error) {
	fa := &tcpip.FullAddress{
		NIC:  tun.ns.NICID,
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}
	protoNum := ipv6.ProtocolNumber
	if addr.Addr().Is4() {
		protoNum = ipv4.ProtocolNumber
	}
	return gonet.DialUDP(tun.ns.Stack, fa, nil, protoNum)
}

// RegisterTCPStatsMetrics registers netstack TCP stats as Prometheus gauges
// that are read at push/scrape time. Call once after creating the TunDevice.
func (tun *TunDevice) RegisterTCPStatsMetrics(reg prometheus.Registerer) {
	s := tun.ns.Stack.Stats().TCP
	gauges := []struct {
		name string
		help string
		fn   func() float64
	}{
		{"tunnel_netstack_tcp_segments_sent_total", "TCP segments sent.", func() float64 { return float64(s.SegmentsSent.Value()) }},
		{"tunnel_netstack_tcp_segments_received_total", "TCP segments received.", func() float64 { return float64(s.ValidSegmentsReceived.Value()) }},
		{"tunnel_netstack_tcp_retransmits_total", "TCP segments retransmitted.", func() float64 { return float64(s.Retransmits.Value()) }},
		{"tunnel_netstack_tcp_fast_retransmit_total", "TCP fast retransmits.", func() float64 { return float64(s.FastRetransmit.Value()) }},
		{"tunnel_netstack_tcp_slow_start_retransmits_total", "TCP slow start retransmits.", func() float64 { return float64(s.SlowStartRetransmits.Value()) }},
		{"tunnel_netstack_tcp_timeouts_total", "TCP RTO timeouts.", func() float64 { return float64(s.Timeouts.Value()) }},
		{"tunnel_netstack_tcp_fast_recovery_total", "TCP fast recovery events.", func() float64 { return float64(s.FastRecovery.Value()) }},
		{"tunnel_netstack_tcp_sack_recovery_total", "TCP SACK recovery events.", func() float64 { return float64(s.SACKRecovery.Value()) }},
		{"tunnel_netstack_tcp_checksum_errors_total", "TCP checksum errors.", func() float64 { return float64(s.ChecksumErrors.Value()) }},
		{"tunnel_netstack_tcp_out_of_order_drops_total", "TCP out-of-order segments dropped because the receive buffer was full.", func() float64 { return float64(s.OutOfOrderDrop.Value()) }},
		{"tunnel_netstack_tcp_established", "Current established TCP connections.", func() float64 { return float64(s.CurrentEstablished.Value()) }},
		{"tunnel_netstack_tcp_resets_sent_total", "TCP resets sent.", func() float64 { return float64(s.ResetsSent.Value()) }},
		{"tunnel_netstack_tcp_resets_received_total", "TCP resets received.", func() float64 { return float64(s.ResetsReceived.Value()) }},
	}
	for _, g := range gauges {
		reg.MustRegister(prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{Name: g.name, Help: g.help},
			g.fn,
		))
	}
}

// ForwardTo forwards all inbound traffic to the upstream network.
func (tun *TunDevice) ForwardTo(ctx context.Context, upstream network.Network) error {
	return tun.ns.ForwardTo(ctx, upstream)
}
