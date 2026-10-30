package vpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/dpeckett/network"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// visitNetwork dials from the netstack, with the visit source for a destination
// in a visited slot. Names go to the VPC DNS servers through the same dials.
type visitNetwork struct {
	*network.NetstackNetwork
	s      *stack.Stack
	nic    tcpip.NICID
	dns    *network.ResolveConfig // Nil uses the resolver of the host.
	visits atomic.Pointer[map[netip.Prefix]netip.Addr]
}

func newVisitNetwork(s *stack.Stack, nic tcpip.NICID, dns *network.ResolveConfig) *visitNetwork {
	if dns != nil && len(dns.Nameservers) == 0 {
		dns = nil
	}
	return &visitNetwork{NetstackNetwork: network.Netstack(s, nic, dns), s: s, nic: nic, dns: dns}
}

// setVisits replaces the visit set: slot prefix to source address.
func (n *visitNetwork) setVisits(visits map[netip.Prefix]netip.Addr) { n.visits.Store(&visits) }

// source returns the visit source of the destination dst.
func (n *visitNetwork) source(dst netip.Addr) (netip.Addr, bool) {
	v := n.visits.Load()
	if v == nil {
		return netip.Addr{}, false
	}
	for pfx, src := range *v {
		if pfx.Contains(dst) {
			return src, true
		}
	}
	return netip.Addr{}, false
}

func (n *visitNetwork) DialContext(ctx context.Context, nw, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("could not parse address %s: %w", address, err)
	}
	port, err := net.LookupPort(nw, portStr)
	if err != nil {
		return nil, fmt.Errorf("could not resolve port %s: %w", portStr, err)
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		hosts, err := n.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("could not resolve hostname %s: %w", host, err)
		}
		for _, h := range hosts {
			a, err := netip.ParseAddr(h)
			if err != nil {
				return nil, fmt.Errorf("could not parse IP address %s: %w", h, err)
			}
			addrs = append(addrs, a)
		}
	}
	var errs []error
	for _, a := range addrs {
		c, err := n.dial(ctx, nw, netip.AddrPortFrom(a.Unmap(), uint16(port)))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("could not connect to any address: %w", errors.Join(errs...))
}

// dial dials dst from its visit source, else as the netstack network does.
func (n *visitNetwork) dial(ctx context.Context, nw string, dst netip.AddrPort) (net.Conn, error) {
	src, ok := n.source(dst.Addr())
	if !ok {
		return n.NetstackNetwork.DialContext(ctx, nw, dst.String())
	}
	proto := ipv6.ProtocolNumber
	if dst.Addr().Is4() {
		proto = ipv4.ProtocolNumber
	}
	local := tcpip.FullAddress{NIC: n.nic, Addr: tcpip.AddrFromSlice(src.AsSlice())}
	remote := tcpip.FullAddress{NIC: n.nic, Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()), Port: dst.Port()}
	switch nw {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialTCPWithBind(ctx, n.s, local, remote, proto)
	case "udp", "udp4", "udp6":
		return gonet.DialUDP(n.s, &local, &remote, proto)
	}
	return nil, fmt.Errorf("unsupported network type: %s", nw)
}

// LookupHost resolves host with the VPC DNS servers through DialContext, so a
// server in a visited slot gets the visit source.
func (n *visitNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	if n.dns == nil {
		return n.NetstackNetwork.LookupHost(ctx, host)
	}
	return n.dns.LookupHost(ctx, host, n.DialContext)
}
