// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"fmt"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const nicID tcpip.NICID = 1

// netstack answers ARP, ICMP, ICMPv6 and NDP on the dedicated interface, and its neighbor table
// gives the next-hop MACs. It has no transport protocols.
type netstack struct {
	s        *stack.Stack
	link     *link
	own      []netip.Prefix
	gw4, gw6 netip.Addr
}

func newNetstack(ifc Interface, mtu uint32, out func(*stack.PacketBuffer) bool) (*netstack, error) {
	n := &netstack{
		s: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol},
		}),
		link: &link{mac: tcpip.LinkAddress(ifc.MAC), mtu: mtu, out: out},
		own:  ifc.Own,
	}
	if err := n.s.CreateNIC(nicID, n.link); err != nil {
		return nil, fmt.Errorf("failed to create the netstack NIC: %s", err)
	}
	var routes []tcpip.Route
	for _, p := range ifc.Own {
		a := tcpip.ProtocolAddress{
			Protocol:          protocol(p.Addr()),
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpipAddr(p.Addr()), PrefixLen: p.Bits()},
		}
		if err := n.s.AddProtocolAddress(nicID, a, stack.AddressProperties{}); err != nil {
			n.close()
			return nil, fmt.Errorf("failed to add %s to the netstack: %s", p, err)
		}
		routes = append(routes, tcpip.Route{Destination: a.AddressWithPrefix.Subnet(), NIC: nicID})
	}
	for _, g := range ifc.Gateways {
		gw := tcpip.Route{Gateway: tcpipAddr(g), NIC: nicID}
		switch {
		case g.Is4() && !n.gw4.IsValid():
			n.gw4, gw.Destination = g, header.IPv4EmptySubnet
		case g.Is6() && !n.gw6.IsValid():
			n.gw6, gw.Destination = g, header.IPv6EmptySubnet
		default:
			continue
		}
		routes = append(routes, gw)
	}
	n.s.SetRouteTable(routes)
	return n, nil
}

func protocol(a netip.Addr) tcpip.NetworkProtocolNumber {
	if a.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

// tcpipAddr converts a as tcpip.AddrFromSlice(a.AsSlice()) does, with no heap allocation: the
// array of AsSlice goes to the heap because AddrFrom4Slice keeps its argument for a panic message.
func tcpipAddr(a netip.Addr) tcpip.Address {
	switch {
	case a.Is4():
		return tcpip.AddrFrom4(a.As4())
	case a.Is6():
		return tcpip.AddrFrom16(a.As16())
	}
	return tcpip.Address{}
}

// nextHop returns the next hop to dst: dst in an own subnet, else the gateway. It is not valid
// when there is no gateway.
func (n *netstack) nextHop(dst netip.Addr) netip.Addr {
	for _, p := range n.own {
		if p.Masked().Contains(dst) {
			return dst
		}
	}
	if dst.Is6() {
		return n.gw6
	}
	return n.gw4
}

// neighbor returns the MAC of hop. A miss starts ARP or NDP and returns false.
func (n *netstack) neighbor(hop netip.Addr) (tcpip.LinkAddress, bool) {
	if !hop.IsValid() {
		return "", false
	}
	addr, proto := tcpipAddr(hop), protocol(hop)
	// The first call has no callback, so that a miss only starts the resolution.
	if err := n.s.GetLinkAddress(nicID, addr, tcpip.Address{}, proto, nil); err != nil {
		return "", false
	}
	// The entry is resolved, so the callback runs before the call returns.
	var mac tcpip.LinkAddress
	err := n.s.GetLinkAddress(nicID, addr, tcpip.Address{}, proto, func(r stack.LinkResolutionResult) {
		if r.Err == nil {
			mac = r.LinkAddress
		}
	})
	return mac, err == nil && mac != ""
}

func (n *netstack) close() {
	n.s.Close()
	n.s.Wait()
}

// link is the link endpoint of the netstack. It adds and parses the Ethernet header, and out
// sends a packet on the dedicated interface.
type link struct {
	mac tcpip.LinkAddress
	mtu uint32
	out func(*stack.PacketBuffer) bool

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
}

var _ stack.LinkEndpoint = (*link)(nil)

// deliver gives a received Ethernet frame to the netstack. It copies the frame.
func (l *link) deliver(frame []byte) {
	l.mu.RLock()
	d := l.dispatcher
	l.mu.RUnlock()
	if d == nil {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	if !l.ParseHeader(pkt) {
		return
	}
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	switch dst := eth.DestinationAddress(); {
	case dst == header.EthernetBroadcastAddress:
		pkt.PktType = tcpip.PacketBroadcast
	case header.IsMulticastEthernetAddress(dst):
		pkt.PktType = tcpip.PacketMulticast
	case dst == l.mac:
		pkt.PktType = tcpip.PacketHost
	default:
		pkt.PktType = tcpip.PacketOtherHost
	}
	d.DeliverNetworkPacket(eth.Type(), pkt)
}

func (l *link) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		if !l.out(pkt) {
			break
		}
		n++
	}
	if n == 0 && pkts.Len() > 0 {
		return 0, &tcpip.ErrWouldBlock{}
	}
	return n, nil
}

func (l *link) AddHeader(pkt *stack.PacketBuffer) {
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	})
}

func (l *link) ParseHeader(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

func (l *link) Attach(d stack.NetworkDispatcher) {
	l.mu.Lock()
	l.dispatcher = d
	l.mu.Unlock()
}

func (l *link) IsAttached() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.dispatcher != nil
}

func (l *link) MTU() uint32                      { return l.mtu }
func (l *link) SetMTU(uint32)                    {}
func (l *link) MaxHeaderLength() uint16          { return header.EthernetMinimumSize }
func (l *link) LinkAddress() tcpip.LinkAddress   { return l.mac }
func (l *link) SetLinkAddress(tcpip.LinkAddress) {}
func (l *link) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired
}
func (l *link) Wait()                                   {}
func (l *link) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareEther }
func (l *link) Close()                                  {}
func (l *link) SetOnCloseAction(func())                 {}
