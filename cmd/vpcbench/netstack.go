// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// netstackNet is the user-space network of the netstack driver, with the
// stack settings of vpc connect.
type netstackNet struct {
	ns *netstack.Stack
}

// startNetstack runs the netstack driver of b on a new stack with address
// self until ctx ends. A non-empty cc sets the TCP congestion control.
func startNetstack(ctx context.Context, fail context.CancelCauseFunc, b *psp.Binding, self netip.Addr, cc string) (overlay, error) {
	ns, err := netstack.NewStack(b.DeviceMTU(), "")
	if err != nil {
		return nil, err
	}
	if cc != "" {
		opt := tcpip.CongestionControlOption(cc)
		if tcpipErr := ns.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcpipErr != nil {
			ns.Close()
			return nil, fmt.Errorf("set TCP congestion control %q: %v", cc, tcpipErr)
		}
	}
	if err := ns.AddAddr(netip.PrefixFrom(self, self.BitLen())); err != nil {
		ns.Close()
		return nil, err
	}
	d, err := b.Netstack(ns.Endpoint)
	if err != nil {
		ns.Close()
		return nil, err
	}
	go func() {
		if err := d.Run(ctx); err != nil && ctx.Err() == nil {
			fail(fmt.Errorf("netstack driver failed: %w", err))
		}
	}()
	return &netstackNet{ns: ns}, nil
}

func (n *netstackNet) fullAddr(a netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv6.ProtocolNumber
	if a.Addr().Is4() {
		proto = ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: n.ns.NICID, Addr: tcpip.AddrFromSlice(a.Addr().AsSlice()), Port: a.Port()}, proto
}

func (n *netstackNet) Listen(a netip.AddrPort) (net.Listener, error) {
	fa, proto := n.fullAddr(a)
	return gonet.ListenTCP(n.ns.Stack, fa, proto)
}

func (n *netstackNet) ListenUDP(a netip.AddrPort) (net.PacketConn, error) {
	fa, proto := n.fullAddr(a)
	return gonet.DialUDP(n.ns.Stack, &fa, nil, proto)
}

func (n *netstackNet) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	fa, proto := n.fullAddr(dst)
	return gonet.DialContextTCP(ctx, n.ns.Stack, fa, proto)
}

func (n *netstackNet) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	fa, proto := n.fullAddr(dst)
	return gonet.DialUDP(n.ns.Stack, nil, &fa, proto)
}

func (n *netstackNet) TCPCounters() (sent, retrans uint64) {
	tcpStats := n.ns.Stack.Stats().TCP
	return tcpStats.SegmentsSent.Value(), tcpStats.Retransmits.Value()
}

func (n *netstackNet) CC() string {
	var cc tcpip.CongestionControlOption
	if err := n.ns.Stack.TransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil {
		return ""
	}
	return string(cc)
}

// Close removes the NIC. Call it after the context of the driver ends.
func (n *netstackNet) Close() { n.ns.Close() }
