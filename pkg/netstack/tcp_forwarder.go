package netstack

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/dpeckett/contextio"
	"github.com/dpeckett/network"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ProtocolHandler is a function that handles packets for a specific protocol.
type ProtocolHandler func(stack.TransportEndpointID, *stack.PacketBuffer) bool

// TCPForwarder forwards TCP connections to an upstream network.
func TCPForwarder(ctx context.Context, ipstack *stack.Stack, upstream network.Network) ProtocolHandler {
	tcpForwarder := tcp.NewForwarder(
		ipstack,
		0,     /* rcvWnd (0 - default) */
		65535, /* maxInFlight */
		tcpHandler(ctx, upstream),
	)

	return tcpForwarder.HandlePacket
}

// Unmap4in6 converts an IPv6 address to an IPv4 address if it is an IPv4-mapped IPv6 address.
// If the address is not an IPv4-mapped IPv6 address, it is returned unchanged.
// If the IPv4 address is zero, returns 127.0.0.1.
// It is following /96 embedding scheme from RFC 6052 (https://datatracker.ietf.org/doc/html/rfc6052#section-2.2).
func Unmap4in6(addr netip.Addr) netip.Addr {
	if !addr.Is6() {
		return addr
	}
	b16 := addr.As16()
	v4addr := netip.AddrFrom4([4]byte{
		b16[12],
		b16[13],
		b16[14],
		b16[15],
	})
	if !v4addr.IsValid() {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return v4addr
}

func tcpHandler(ctx context.Context, upstream network.Network) func(req *tcp.ForwarderRequest) {
	return func(req *tcp.ForwarderRequest) {
		reqDetails := req.ID()

		srcAddrPort := netip.AddrPortFrom(addrFromNetstackIP(reqDetails.RemoteAddress), reqDetails.RemotePort)
		dstAddrPort := netip.AddrPortFrom(
			Unmap4in6(addrFromNetstackIP(reqDetails.LocalAddress)),
			reqDetails.LocalPort,
		)

		logger := slog.With(
			slog.String("src", srcAddrPort.String()),
			slog.String("dst", dstAddrPort.String()))

		logger.Info("Forwarding TCP session")

		go func() {
			defer logger.Debug("Session finished")

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			var wq waiter.Queue
			ep, tcpipErr := req.CreateEndpoint(&wq)
			if tcpipErr != nil {
				logger.Warn("Failed to create local endpoint",
					slog.String("error", tcpipErr.String()))

				req.Complete(true) // send RST
				return
			}

			// Cancel the context when the connection is closed.
			waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp)
			wq.EventRegister(&waitEntry)
			defer wq.EventUnregister(&waitEntry)

			go func() {
				select {
				case <-ctx.Done():
				case <-notifyCh:
					logger.Debug("tcpHandler notifyCh fired - canceling context")
					cancel()
				}
			}()

			// Disable Nagle's algorithm.
			ep.SocketOptions().SetDelayOption(false)
			// Enable keep-alive to make detecting dead connections easier.
			ep.SocketOptions().SetKeepAlive(true)

			local := gonet.NewTCPConn(&wq, ep)
			defer local.Close()

			// Connect to the destination.
			remote, err := upstream.DialContext(ctx, "tcp", dstAddrPort.String())
			if err != nil {
				logger.Warn("Failed to dial destination", slog.Any("error", err))

				req.Complete(true) // send RST
				return
			}
			defer remote.Close()

			logger.Info("Connected to upstream")

			// Start forwarding.
			wn, err := contextio.SpliceContext(ctx, local, remote, nil)
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("Failed to forward session", slog.Any("error", err))

				req.Complete(true) // send RST
				return
			}
			logger.Info("Connection closed", slog.Int64("bytes_written", wn))

			req.Complete(false) // send FIN
		}()
	}
}

func addrFromNetstackIP(ip tcpip.Address) netip.Addr {
	switch ip.Len() {
	case 4:
		return netip.AddrFrom4(ip.As4())
	case 16:
		return netip.AddrFrom16(ip.As16())
	}
	return netip.Addr{}
}
