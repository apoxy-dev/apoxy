package netstack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"

	"github.com/apoxy-dev/icx"
	"github.com/dpeckett/network"
	"golang.org/x/sync/errgroup"

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

	stdnet "net"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
)

type ICXNetwork struct {
	network.Network
	handler        *icx.Handler
	phy            *l2pc.L2PacketConn
	ep             *channel.Endpoint
	stack          *stack.Stack
	ipt            *IPTables
	nicID          tcpip.NICID
	pcapFile       *os.File
	incomingPacket chan *buffer.View
	pktPool        sync.Pool
	closeOnce      sync.Once
}

// NewICXNetwork creates a new ICXNetwork instance with the given handler, physical connection, MTU, and resolve configuration.
// If pcapPath is provided, it will create a packet sniffer that writes to the specified file.
// The handler must be configured in layer3 mode.
func NewICXNetwork(handler *icx.Handler, phy *l2pc.L2PacketConn, pathMTU int, resolveConf *network.ResolveConfig, pcapPath string) (*ICXNetwork, error) {
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
	tcpCCOpt := tcpip.CongestionControlOption("cubic")
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpCCOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP congestion control: %v", tcpipErr)
	}
	tcpDelayOpt := tcpip.TCPDelayEnabled(false)
	if tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpDelayOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP delay: %v", tcpipErr)
	}

	nicID := ipstack.NextNICID()
	linkEP := channel.New(4096, uint32(icx.MTU(pathMTU)), "")
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

	net := &ICXNetwork{
		Network:        network.Netstack(ipstack, nicID, resolveConf),
		handler:        handler,
		phy:            phy,
		ep:             linkEP,
		stack:          ipstack,
		ipt:            ipt,
		nicID:          nicID,
		pcapFile:       pcapFile,
		incomingPacket: make(chan *buffer.View),
		pktPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, pathMTU)
				return &b
			},
		},
	}
	net.ep.AddNotify(net)

	return net, nil
}

// WriteNotify is called by the channel endpoint when netstack has an outbound packet ready.
func (net *ICXNetwork) WriteNotify() {
	pkt := net.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	net.incomingPacket <- view
}

// Close cleans up the network stack and closes the underlying resources.
func (net *ICXNetwork) Close() error {
	net.closeOnce.Do(func() {
		net.stack.RemoveNIC(net.nicID)

		net.ep.Close()

		if net.incomingPacket != nil {
			close(net.incomingPacket)
		}

		if net.pcapFile != nil {
			_ = net.pcapFile.Close()
		}
	})

	return nil
}

// Start copies packets to and from netstack and icx.
// This is a blocking call that runs until either side is closed.
func (net *ICXNetwork) Start() error {
	var g errgroup.Group

	// Outbound: netstack (L3) -> ICX -> L2PacketConn.WriteFrame
	g.Go(func() error {
		for {
			view, ok := <-net.incomingPacket
			if !ok {
				return stdnet.ErrClosed // channel closed => done
			}
			ip := view.AsSlice() // raw IP bytes (v4 or v6)

			phyFrame := net.pktPool.Get().(*[]byte)
			*phyFrame = (*phyFrame)[:cap(*phyFrame)]
			n, _ := net.handler.VirtToPhy(ip, *phyFrame)
			if n > 0 {
				if err := net.phy.WriteFrame((*phyFrame)[:n]); err != nil {
					net.pktPool.Put(phyFrame)
					return fmt.Errorf("writing phy frame failed: %w", err)
				}
			}
			net.pktPool.Put(phyFrame)
		}
	})

	// Inbound: L2PacketConn.ReadFrame -> ICX -> netstack.InjectInbound(L3)
	g.Go(func() error {
		for {
			phyFrame := net.pktPool.Get().(*[]byte)
			*phyFrame = (*phyFrame)[:cap(*phyFrame)]

			n, err := net.phy.ReadFrame(*phyFrame)
			if err != nil {
				net.pktPool.Put(phyFrame)
				return fmt.Errorf("reading phy frame failed: %w", err)
			}
			if n == 0 {
				net.pktPool.Put(phyFrame)
				continue
			}

			virtFrame := net.pktPool.Get().(*[]byte)
			*virtFrame = (*virtFrame)[:cap(*virtFrame)]

			vn := net.handler.PhyToVirt((*phyFrame)[:n], *virtFrame)
			net.pktPool.Put(phyFrame)

			if vn == 0 {
				net.pktPool.Put(virtFrame)
				continue
			}

			payload := (*virtFrame)[:vn] // raw IP (L3)
			switch payload[0] >> 4 {
			case header.IPv4Version:
				pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(payload),
				})
				net.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
				pkb.DecRef()
			case header.IPv6Version:
				pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(payload),
				})
				net.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
				pkb.DecRef()
			default:
				// drop silently
				net.pktPool.Put(virtFrame)
			}
		}
	})

	// Wait for either side to finish. If inbound ends with an error (e.g., phy closed),
	// that error is returned; if both exit cleanly, Wait returns nil.
	if err := g.Wait(); err != nil && !errors.Is(err, stdnet.ErrClosed) {
		return fmt.Errorf("packet splicing failed: %w", err)
	}

	return nil
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
	return nil
}
