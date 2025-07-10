package netstack

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"

	"github.com/dpeckett/network"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
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

var _ tun.Device = (*TunDevice)(nil)

type TunDevice struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	nicID          tcpip.NICID
	pcapFile       *os.File
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	closed         atomic.Bool
}

func NewTunDevice(pcapPath string) (*TunDevice, error) {
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

	nicID := ipstack.NextNICID()
	linkEP := channel.New(4096, uint32(IPv6MinMTU), "")
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
		nicID:          nicID,
		pcapFile:       pcapFile,
		events:         make(chan tun.Event, 1),
		incomingPacket: make(chan *buffer.View),
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

	return nil
}
