// icx_network.go
package netstack

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/apoxy-dev/icx"
	icxns "github.com/apoxy-dev/icx/vtep/netstack"
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

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
)

// TODO (dpeckett): nuke this at some point and merge the logic into the router.
type ICXNetwork struct {
	network.Network
	handler  *icx.Handler
	phy      *l2pc.L2PacketConn
	ep       *channel.Endpoint
	stack    *stack.Stack
	ipt      *IPTables
	nicID    tcpip.NICID
	pcapFile *os.File

	// dp is the shared ICX netstack datapath driver (icx/vtep/netstack). It owns
	// the channel.Endpoint <-> engine <-> underlay pump; this type contributes
	// the gVisor stack, SNAT, and TCP/UDP forwarders around it.
	dp *icxns.Datapath

	closeOnce sync.Once
}

// l2Underlay adapts *l2pc.L2PacketConn to the icx netstack datapath's Underlay.
// WriteFrames reuses a scratch []batchpc.Message; the datapath's outbound pump
// is single-goroutine, so the scratch needs no synchronization.
type l2Underlay struct {
	phy  *l2pc.L2PacketConn
	msgs []batchpc.Message
}

func (u *l2Underlay) ReadFrame(buf []byte) (int, error) {
	return u.phy.ReadFrame(buf)
}

func (u *l2Underlay) WriteFrames(frames [][]byte) (int, error) {
	if cap(u.msgs) < len(frames) {
		u.msgs = make([]batchpc.Message, len(frames))
	}
	msgs := u.msgs[:len(frames)]
	for i, f := range frames {
		msgs[i].Buf = f
	}
	return u.phy.WriteBatchFrames(msgs, 0)
}

// NewICXNetwork creates a new ICXNetwork instance with the given handler, physical connection, MTU, and resolve configuration.
// If pcapPath is provided, it will create a packet sniffer that writes to the specified file.
// The handler must be configured in layer3 mode.
func NewICXNetwork(handler *icx.Handler, phy *l2pc.L2PacketConn, mtu int, resolveConf *network.ResolveConfig, pcapPath string) (*ICXNetwork, error) {
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

	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	// The gVisor netstack only registers the reno and cubic congestion-control
	// algorithms; "bbr" is not built in and SetTransportProtocolOption rejects it
	// with ErrNoSuchFile, which previously failed ICXNetwork construction outright.
	// cubic is the modern loss-based default and a strict upgrade over reno here.
	tcpCCOpt := tcpip.CongestionControlOption("cubic")
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpCCOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP congestion control: %v", tcpipErr)
	}
	tcpDelayOpt := tcpip.TCPDelayEnabled(false)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpDelayOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP delay: %v", tcpipErr)
	}

	// High-performance TCP buffer settings.
	tcpRcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     64 << 10,  // 64 KiB
		Default: 2 << 20,   // 2 MiB
		Max:     16 << 20,  // 16 MiB
	}
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRcvBuf); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP receive buffer size: %v", tcpipErr)
	}
	tcpSndBuf := tcpip.TCPSendBufferSizeRangeOption{
		Min:     64 << 10,  // 64 KiB
		Default: 2 << 20,   // 2 MiB
		Max:     16 << 20,  // 16 MiB
	}
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpSndBuf); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP send buffer size: %v", tcpipErr)
	}
	tcpModBuf := tcpip.TCPModerateReceiveBufferOption(true)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpModBuf); tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP moderate receive buffer: %v", tcpipErr)
	}
	tcpTWReuse := tcpip.TCPTimeWaitReuseOption(tcpip.TCPTimeWaitReuseGlobal)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTWReuse); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP TIME_WAIT reuse: %v", tcpipErr)
	}
	tcpTWTimeout := tcpip.TCPTimeWaitTimeoutOption(10 * time.Second)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTWTimeout); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP TIME_WAIT timeout: %v", tcpipErr)
	}
	tcpLingerTimeout := tcpip.TCPLingerTimeoutOption(10 * time.Second)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpLingerTimeout); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP linger timeout: %v", tcpipErr)
	}
	tcpMinRTO := tcpip.TCPMinRTOOption(100 * time.Millisecond)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpMinRTO); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP min RTO: %v", tcpipErr)
	}

	nicID := ipstack.NextNICID()
	linkEP := channel.New(4096, uint32(mtu), "")
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
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	dp, err := icxns.New(icxns.Config{
		Engine:   handler,
		Endpoint: linkEP,
		Underlay: &l2Underlay{phy: phy},
	})
	if err != nil {
		_ = phy.Close()
		return nil, fmt.Errorf("could not create ICX netstack datapath: %w", err)
	}

	net := &ICXNetwork{
		Network:  network.Netstack(ipstack, nicID, resolveConf),
		handler:  handler,
		phy:      phy,
		ep:       linkEP,
		stack:    ipstack,
		ipt:      ipt,
		nicID:    nicID,
		pcapFile: pcapFile,
		dp:       dp,
	}

	return net, nil
}

// Close cleans up the network stack and closes the underlying resources.
func (net *ICXNetwork) Close() error {
	net.closeOnce.Do(func() {
		if net.dp != nil {
			_ = net.dp.Close()
		}

		net.stack.RemoveNIC(net.nicID)

		net.ep.Close()

		if net.pcapFile != nil {
			_ = net.pcapFile.Close()
		}
	})

	return nil
}

// Start copies packets to and from netstack and icx.
// Start runs the netstack <-> ICX datapath until ctx is cancelled or the
// underlying transport (phy) is closed. It blocks and should run in its own
// goroutine. The two pump loops (channel.Endpoint <-> engine <-> underlay) now
// live in the shared icx/vtep/netstack driver; this method just drives it.
func (net *ICXNetwork) Start(ctx context.Context) error {
	return net.dp.Run(ctx)
}

func (net *ICXNetwork) AddAddr(addr netip.Prefix) error {
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

	tcpipErr := net.stack.AddProtocolAddress(net.nicID, protoAddr, stack.AddressProperties{})
	if tcpipErr != nil {
		return fmt.Errorf("could not add protocol address: %v", tcpipErr)
	}

	slog.Info("Adding addr to SNAT", slog.String("addr", addr.String()))
	if addr.Addr().Is4() {
		net.ipt.SNATv4.add(protoAddr.AddressWithPrefix.Address)
	} else if addr.Addr().Is6() {
		net.ipt.SNATv6.add(protoAddr.AddressWithPrefix.Address)
	}
	return nil
}

func (net *ICXNetwork) DelAddr(addr netip.Prefix) error {
	var nsAddr tcpip.Address
	if addr.Addr().Is4() {
		nsAddr = tcpip.AddrFrom4(addr.Addr().As4())
	} else if addr.Addr().Is6() {
		nsAddr = tcpip.AddrFrom16(addr.Addr().As16())
	}

	slog.Info("Removing protocol address", slog.String("addr", addr.Addr().String()))

	if err := net.stack.RemoveAddress(net.nicID, nsAddr); err != nil {
		return fmt.Errorf("could not remove address: %v", err)
	}

	slog.Info("Removing addr from SNAT", slog.String("addr", addr.String()))
	if addr.Addr().Is4() {
		net.ipt.SNATv4.del(nsAddr)
	} else if addr.Addr().Is6() {
		net.ipt.SNATv6.del(nsAddr)
	}
	return nil
}

// ForwardTo forwards all inbound TCP traffic to the upstream network.
func (net *ICXNetwork) ForwardTo(ctx context.Context, upstream network.Network) error {
	// Allow outgoing packets to have a source address different from the NIC.
	if tcpipErr := net.stack.SetSpoofing(net.nicID, true); tcpipErr != nil {
		return fmt.Errorf("failed to enable spoofing: %v", tcpipErr)
	}

	// Allow incoming packets to have a destination address different from the NIC.
	if tcpipErr := net.stack.SetPromiscuousMode(net.nicID, true); tcpipErr != nil {
		return fmt.Errorf("failed to enable promiscuous mode: %v", tcpipErr)
	}

	tcpForwarder := TCPForwarder(ctx, net.stack, upstream)
	net.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder)

	udpForwarder := UDPForwarder(ctx, net.stack, upstream)
	net.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder)

	return nil
}
