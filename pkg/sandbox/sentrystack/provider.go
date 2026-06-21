//go:build linux

package sentrystack

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// provider implements socket.Provider for AF_INET and AF_INET6 by routing
// socket() calls through our sentrystack.Stack.
//
// gVisor's netstack package registers its own AF_INET/AF_INET6 providers
// at init() time; those return nil when t.NetworkContext() isn't an
// *netstack.Stack (which it won't be for us — it's an *sentrystack.Stack).
// The sentry then iterates to the next provider. That's how both stay
// registered without conflict, and how a future "host-mode" sandbox in
// the same binary could keep using netstack while sandboxes use
// sentrystack.
type provider struct {
	family   int
	netProto tcpip.NetworkProtocolNumber
}

// Socket creates a new socket FD on the embedded *tcpip.Stack. Mirrors
// netstack/provider.go::Socket but switches the type assertion to
// *sentrystack.Stack and reaches the inner stack via tcpipStack().
//
// We deliberately don't support AF_PACKET or SOCK_RAW: sandboxes
// should never see raw frames, and CAP_NET_RAW is dropped in the
// container config. If a sandbox somehow tries, the sentry returns
// ENOPROTOOPT — matching the spirit of the threat model.
func (p *provider) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	netCtx := t.NetworkContext()
	if netCtx == nil {
		return nil, nil
	}
	s, ok := netCtx.(*Stack)
	if !ok {
		// Let other providers (e.g. netstack's) handle this network
		// context.
		return nil, nil
	}

	transProto, err := transportProtocol(stype, protocol)
	if err != nil {
		return nil, err
	}

	ts := s.tcpipStack()
	if ts == nil {
		// Init hasn't run yet (or failed). Fail closed.
		return nil, syserr.ErrInvalidArgument
	}

	wq := &waiter.Queue{}
	ep, e := ts.NewEndpoint(transProto, p.netProto, wq)
	if e != nil {
		return nil, syserr.TranslateNetstackError(e)
	}
	ep.SetOwner(t)

	return netstack.New(t, p.family, stype, int(transProto), wq, ep)
}

// Pair is not supported — socketpair on AF_INET/AF_INET6 has never been
// valid on Linux either.
func (*provider) Pair(*kernel.Task, linux.SockType, int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	return nil, nil, nil
}

// transportProtocol maps (stype, protocol) onto a tcpip transport
// protocol number, restricted to TCP/UDP/ICMP. SOCK_RAW is rejected;
// see the type-level comment.
func transportProtocol(stype linux.SockType, protocol int) (tcpip.TransportProtocolNumber, *syserr.Error) {
	switch stype {
	case linux.SOCK_STREAM:
		if protocol != 0 && protocol != unix.IPPROTO_TCP {
			return 0, syserr.ErrInvalidArgument
		}
		return tcp.ProtocolNumber, nil
	case linux.SOCK_DGRAM:
		switch protocol {
		case 0, unix.IPPROTO_UDP:
			return udp.ProtocolNumber, nil
		case unix.IPPROTO_ICMP:
			return header.ICMPv4ProtocolNumber, nil
		case unix.IPPROTO_ICMPV6:
			return header.ICMPv6ProtocolNumber, nil
		}
	}
	return 0, syserr.ErrProtocolNotSupported
}

// registerProviders is called from package init() to register both
// AF_INET and AF_INET6 providers.
func registerProviders() {
	socket.RegisterProvider(linux.AF_INET, &provider{
		family:   linux.AF_INET,
		netProto: ipv4.ProtocolNumber,
	})
	socket.RegisterProvider(linux.AF_INET6, &provider{
		family:   linux.AF_INET6,
		netProto: ipv6.ProtocolNumber,
	})
}
