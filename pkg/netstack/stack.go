package netstack

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/dpeckett/network"

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

// Stack is a gVisor network stack with one NIC on a channel endpoint. The
// caller moves packets in and out of Endpoint.
type Stack struct {
	Stack    *stack.Stack
	Endpoint *channel.Endpoint
	NICID    tcpip.NICID

	ipt      *IPTables // Nil for a stack without iptables.
	filter   *inFilter // Nil for a stack with iptables.
	pcapFile *os.File
}

// Option configures NewStack.
type Option func(*stackOptions)

type stackOptions struct {
	noIPTables bool
}

// WithoutIPTables makes a stack with no iptables, so that no packet goes
// through conntrack, and with no SNAT. A filter with no state lets in only
// TCP, UDP, ICMP errors, and ICMP echo requests to an address of the stack.
// Use it for a stack with one address.
func WithoutIPTables() Option {
	return func(o *stackOptions) { o.noIPTables = true }
}

// NewStack makes a stack with the tunnel TCP options and one NIC with the
// given MTU. The NIC routes all addresses. Set pcapPath to write a packet
// capture of the NIC.
func NewStack(mtu int, pcapPath string, opts ...Option) (*Stack, error) {
	var o stackOptions
	for _, opt := range opts {
		opt(&o)
	}
	sopts := stack.Options{
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
	var ipt *IPTables
	if !o.noIPTables {
		ipt = newIPTables()
		sopts.DefaultIPTables = ipt.defaultIPTables
	}
	ipstack := stack.New(sopts)

	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	tcpCCOpt := tcpip.CongestionControlOption(TCPCongestionControl)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpCCOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP congestion control: %v", tcpipErr)
	}
	tcpDelayOpt := tcpip.TCPDelayEnabled(false)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpDelayOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP delay: %v", tcpipErr)
	}

	// High-performance TCP buffer settings. The window is half the receive
	// buffer, and out-of-order segments use 1.4x to 2.2x their size in memory.
	tcpRcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     64 << 10, // 64 KiB
		Default: 4 << 20,  // 4 MiB
		Max:     32 << 20, // 32 MiB
	}
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRcvBuf); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP receive buffer size: %v", tcpipErr)
	}
	tcpSndBuf := tcpip.TCPSendBufferSizeRangeOption{
		Min:     64 << 10, // 64 KiB
		Default: 2 << 20,  // 2 MiB
		Max:     16 << 20, // 16 MiB
	}
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpSndBuf); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP send buffer size: %v", tcpipErr)
	}
	// Let the stack auto-tune receive buffer based on RTT and throughput.
	tcpModBuf := tcpip.TCPModerateReceiveBufferOption(true)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpModBuf); tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP moderate receive buffer: %v", tcpipErr)
	}
	// Allow reusing sockets in TIME_WAIT for new connections (like tcp_tw_reuse).
	tcpTWReuse := tcpip.TCPTimeWaitReuseOption(tcpip.TCPTimeWaitReuseGlobal)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTWReuse); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP TIME_WAIT reuse: %v", tcpipErr)
	}
	// Shorten TIME_WAIT from the default 60s.
	tcpTWTimeout := tcpip.TCPTimeWaitTimeoutOption(10 * time.Second)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTWTimeout); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP TIME_WAIT timeout: %v", tcpipErr)
	}
	// Shorten FIN_WAIT_2 linger from the default 60s.
	tcpLingerTimeout := tcpip.TCPLingerTimeoutOption(10 * time.Second)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpLingerTimeout); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP linger timeout: %v", tcpipErr)
	}
	// The min RTO is 200 ms, as in Linux. The RTT under load can be more than 100 ms.
	tcpMinRTO := tcpip.TCPMinRTOOption(200 * time.Millisecond)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpMinRTO); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP min RTO: %v", tcpipErr)
	}

	nicID := ipstack.NextNICID()
	linkEP := channel.New(4096, uint32(mtu), "")
	var nicEP stack.LinkEndpoint = linkEP
	var filter *inFilter
	if o.noIPTables {
		filter = newInFilter(linkEP)
		nicEP = filter
	}

	var pcapFile *os.File
	if pcapPath != "" {
		var err error
		pcapFile, err = os.Create(pcapPath)
		if err != nil {
			return nil, fmt.Errorf("could not create pcap file: %w", err)
		}
		nicEP, err = sniffer.NewWithWriter(linkEP, pcapFile, linkEP.MTU())
		if err != nil {
			_ = pcapFile.Close()
			return nil, fmt.Errorf("could not create packet sniffer: %w", err)
		}
	}

	if tcpipErr := ipstack.CreateNIC(nicID, nicEP); tcpipErr != nil {
		if pcapFile != nil {
			_ = pcapFile.Close()
		}
		return nil, fmt.Errorf("could not create NIC: %v", tcpipErr)
	}

	ipstack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	return &Stack{
		Stack:    ipstack,
		Endpoint: linkEP,
		NICID:    nicID,
		ipt:      ipt,
		filter:   filter,
		pcapFile: pcapFile,
	}, nil
}

// Close removes the NIC, stops the stack and waits for its goroutines, and
// closes the endpoint and the packet capture.
func (s *Stack) Close() {
	// Without the NIC, no packet can make a new endpoint that Wait then waits for.
	s.Stack.RemoveNIC(s.NICID)
	s.Stack.Close()
	s.Stack.Wait()
	s.Endpoint.Close()
	if s.pcapFile != nil {
		_ = s.pcapFile.Close()
	}
}

// AddAddr adds addr to the NIC, and to the SNAT source addresses or the
// local addresses of the filter.
func (s *Stack) AddAddr(addr netip.Prefix) error {
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

	if tcpipErr := s.Stack.AddProtocolAddress(s.NICID, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
		return fmt.Errorf("could not add protocol address: %v", tcpipErr)
	}

	if s.filter != nil {
		s.filter.add(protoAddr.AddressWithPrefix.Address)
		return nil
	}

	slog.Info("Adding addr to SNAT", slog.String("addr", addr.String()))

	if addr.Addr().Is4() {
		s.ipt.SNATv4.add(protoAddr.AddressWithPrefix.Address)
	} else if addr.Addr().Is6() {
		s.ipt.SNATv6.add(protoAddr.AddressWithPrefix.Address)
	}
	return nil
}

// DelAddr removes addr from the NIC, and from the SNAT source addresses or
// the local addresses of the filter.
func (s *Stack) DelAddr(addr netip.Prefix) error {
	var nsAddr tcpip.Address
	if addr.Addr().Is4() {
		nsAddr = tcpip.AddrFrom4(addr.Addr().As4())
	} else if addr.Addr().Is6() {
		nsAddr = tcpip.AddrFrom16(addr.Addr().As16())
	}

	slog.Info("Removing protocol address", slog.String("addr", addr.Addr().String()))

	if err := s.Stack.RemoveAddress(s.NICID, nsAddr); err != nil {
		return fmt.Errorf("could not remove address: %v", err)
	}

	if s.filter != nil {
		s.filter.del(nsAddr)
		return nil
	}

	slog.Info("Removing addr from SNAT", slog.String("addr", addr.String()))

	if addr.Addr().Is4() {
		s.ipt.SNATv4.del(nsAddr)
	} else if addr.Addr().Is6() {
		s.ipt.SNATv6.del(nsAddr)
	}
	return nil
}

// ForwardTo forwards all inbound TCP and UDP traffic to the upstream network.
func (s *Stack) ForwardTo(ctx context.Context, upstream network.Network) error {
	// Allow outgoing packets to have a source address different from the NIC.
	if tcpipErr := s.Stack.SetSpoofing(s.NICID, true); tcpipErr != nil {
		return fmt.Errorf("failed to enable spoofing: %v", tcpipErr)
	}

	// Allow incoming packets to have a destination address different from the NIC.
	if tcpipErr := s.Stack.SetPromiscuousMode(s.NICID, true); tcpipErr != nil {
		return fmt.Errorf("failed to enable promiscuous mode: %v", tcpipErr)
	}

	s.Stack.SetTransportProtocolHandler(tcp.ProtocolNumber, TCPForwarder(ctx, s.Stack, upstream))
	s.Stack.SetTransportProtocolHandler(udp.ProtocolNumber, UDPForwarder(ctx, s.Stack, upstream))
	return nil
}

// Network returns the network that dials from the stack.
func (s *Stack) Network(resolveConf *network.ResolveConfig) *network.NetstackNetwork {
	return network.Netstack(s.Stack, s.NICID, resolveConf)
}
