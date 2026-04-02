package netstack

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dpeckett/network"
	"github.com/prometheus/client_golang/prometheus"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const IPv6MinMTU = 1280 // IPv6 minimum MTU, required for some PPPoE links.

// TunnelMTU is the MTU used for tunnel TUN devices. Sized to fit in a single
// QUIC datagram after PMTUD on a typical 1500-byte internet path:
// 1500 (Ethernet) - 20 (IP) - 8 (UDP) - ~26 (QUIC framing) - 1 (contextID) ≈ 1445.
// We use 1420 to leave headroom for path variance.
const TunnelMTU = 1420

var _ tun.Device = (*TunDevice)(nil)

type TunDevice struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	ipt            *IPTables
	nicID          tcpip.NICID
	pcapFile       *os.File
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	closed         atomic.Bool
}

func NewTunDevice(pcapPath string) (*TunDevice, error) {
	ipt := newIPTables()
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		DefaultIPTables: ipt.defaultIPTables,
	}

	ipstack := stack.New(opts)

	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // Enable SACK cuz we're not savages.
	tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	tcpCCOpt := tcpip.CongestionControlOption("cubic")
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpCCOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP congestion control: %v", tcpipErr)
	}
	tcpDelayOpt := tcpip.TCPDelayEnabled(false)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpDelayOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP delay: %v", tcpipErr)
	}

	// High-performance TCP buffer settings.
	tcpRcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     64 << 10, // 64 KiB
		Default: 2 << 20,  // 2 MiB
		Max:     16 << 20, // 16 MiB
	}
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRcvBuf)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP receive buffer size: %v", tcpipErr)
	}
	tcpSndBuf := tcpip.TCPSendBufferSizeRangeOption{
		Min:     64 << 10, // 64 KiB
		Default: 2 << 20,  // 2 MiB
		Max:     16 << 20, // 16 MiB
	}
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpSndBuf)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP send buffer size: %v", tcpipErr)
	}
	// Let the stack auto-tune receive buffer based on RTT and throughput.
	tcpModBuf := tcpip.TCPModerateReceiveBufferOption(true)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpModBuf)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP moderate receive buffer: %v", tcpipErr)
	}
	// Allow reusing sockets in TIME_WAIT for new connections (like tcp_tw_reuse).
	tcpTWReuse := tcpip.TCPTimeWaitReuseOption(tcpip.TCPTimeWaitReuseGlobal)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTWReuse)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP TIME_WAIT reuse: %v", tcpipErr)
	}
	// Shorten TIME_WAIT from the default 60s.
	tcpTWTimeout := tcpip.TCPTimeWaitTimeoutOption(10 * time.Second)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTWTimeout)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP TIME_WAIT timeout: %v", tcpipErr)
	}
	// Shorten FIN_WAIT_2 linger from the default 60s.
	tcpLingerTimeout := tcpip.TCPLingerTimeoutOption(10 * time.Second)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpLingerTimeout)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP linger timeout: %v", tcpipErr)
	}
	// Reduce min RTO to improve latency on retransmits (default 200ms).
	tcpMinRTO := tcpip.TCPMinRTOOption(100 * time.Millisecond)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpMinRTO)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP min RTO: %v", tcpipErr)
	}

	nicID := ipstack.NextNICID()
	linkEP := channel.New(4096, uint32(TunnelMTU), "")
	var nicEP stack.LinkEndpoint = linkEP

	var pcapFile *os.File
	if pcapPath != "" {
		var err error
		pcapFile, err = os.Create(pcapPath)
		if err != nil {
			return nil, fmt.Errorf("could not create pcap file: %w", err)
		}

		nicEP, err = sniffer.NewWithWriter(linkEP, pcapFile, linkEP.MTU())
		if err != nil {
			return nil, fmt.Errorf("could not create packet sniffer: %w", err)
		}
	}

	if tcpipErr := ipstack.CreateNIC(nicID, nicEP); tcpipErr != nil {
		return nil, fmt.Errorf("could not create NIC: %v", tcpipErr)
	}

	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	tunDev := &TunDevice{
		ep:             linkEP,
		stack:          ipstack,
		ipt:            ipt,
		nicID:          nicID,
		pcapFile:       pcapFile,
		events:         make(chan tun.Event, 1),
		incomingPacket: make(chan *buffer.View, 1024),
		mtu:            int(linkEP.MTU()),
	}
	tunDev.ep.AddNotify(tunDev)
	tunDev.events <- tun.EventUp

	return tunDev, nil
}

func (tun *TunDevice) AddAddr(addr netip.Prefix) error {
	var protoNumber tcpip.NetworkProtocolNumber
	if addr.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else if addr.Addr().Is6() {
		protoNumber = ipv6.ProtocolNumber
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          protoNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(addr.Addr().AsSlice()).WithPrefix(),
	}

	slog.Info("Adding protocol address", slog.String("addr", addr.String()))

	tcpipErr := tun.stack.AddProtocolAddress(tun.nicID, protoAddr, stack.AddressProperties{})
	if tcpipErr != nil {
		return fmt.Errorf("could not add protocol address: %v", tcpipErr)
	}

	slog.Info("Adding addr to SNAT", slog.String("addr", addr.String()))

	if addr.Addr().Is4() {
		tun.ipt.SNATv4.add(protoAddr.AddressWithPrefix.Address)
	} else if addr.Addr().Is6() {
		tun.ipt.SNATv6.add(protoAddr.AddressWithPrefix.Address)
	}

	return nil
}

func (tun *TunDevice) DelAddr(addr netip.Prefix) error {
	var nsAddr tcpip.Address
	if addr.Addr().Is4() {
		nsAddr = tcpip.AddrFrom4(addr.Addr().As4())
	} else if addr.Addr().Is6() {
		nsAddr = tcpip.AddrFrom16(addr.Addr().As16())
	}

	slog.Info("Removing protocol address", slog.String("addr", addr.Addr().String()))

	if err := tun.stack.RemoveAddress(tun.nicID, nsAddr); err != nil {
		return fmt.Errorf("could not remove address: %v", err)
	}

	slog.Info("Removing addr from SNAT", slog.String("addr", addr.String()))

	if addr.Addr().Is4() {
		tun.ipt.SNATv4.del(nsAddr)
	} else if addr.Addr().Is6() {
		tun.ipt.SNATv6.del(nsAddr)
	}

	return nil
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

	view, ok := <-tun.incomingPacket
	if !ok {
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
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
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

	pkt := tun.ep.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

func (tun *TunDevice) Close() error {
	if tun.closed.Swap(true) {
		return nil
	}

	tun.stack.RemoveNIC(tun.nicID)

	if tun.events != nil {
		close(tun.events)
	}

	tun.ep.Close()

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	if tun.pcapFile != nil {
		_ = tun.pcapFile.Close()
	}

	return nil
}

// Network returns the network abstraction for the TUN device.
func (tun *TunDevice) Network(resolveConf *network.ResolveConfig) *network.NetstackNetwork {
	return network.Netstack(tun.stack, tun.nicID, resolveConf)
}

// LocalAddresses returns the list of local addresses assigned to the TUN device.
func (tun *TunDevice) LocalAddresses() ([]netip.Prefix, error) {
	nic := tun.stack.NICInfo()[tun.nicID]

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
		NIC:  tun.nicID,
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}
	protoNum := ipv6.ProtocolNumber
	if addr.Addr().Is4() {
		protoNum = ipv4.ProtocolNumber
	}
	return gonet.DialUDP(tun.stack, fa, nil, protoNum)
}

// RegisterTCPStatsMetrics registers netstack TCP stats as Prometheus gauges
// that are read at push/scrape time. Call once after creating the TunDevice.
func (tun *TunDevice) RegisterTCPStatsMetrics(reg prometheus.Registerer) {
	s := tun.stack.Stats().TCP
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
	// Allow outgoing packets to have a source address different from the address
	// assigned to the NIC.
	if tcpipErr := tun.stack.SetSpoofing(tun.nicID, true); tcpipErr != nil {
		return fmt.Errorf("failed to enable spoofing: %v", tcpipErr)
	}

	// Allow incoming packets to have a destination address different from the
	// address assigned to the NIC.
	if tcpipErr := tun.stack.SetPromiscuousMode(tun.nicID, true); tcpipErr != nil {
		return fmt.Errorf("failed to enable promiscuous mode: %v", tcpipErr)
	}

	tcpForwarder := TCPForwarder(ctx, tun.stack, upstream)
	tun.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder)

	udpForwarder := UDPForwarder(ctx, tun.stack, upstream)
	tun.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder)

	return nil
}
