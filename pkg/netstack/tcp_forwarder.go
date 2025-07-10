package netstack

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/dpeckett/contextio"
	"github.com/dpeckett/network"
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

func tcpHandler(ctx context.Context, upstream network.Network) func(req *tcp.ForwarderRequest) {
	return func(req *tcp.ForwarderRequest) {
		reqDetails := req.ID()

		srcAddrPort := netip.AddrPortFrom(addrFromNetstackIP(reqDetails.RemoteAddress), reqDetails.RemotePort)
		dstAddrPort := netip.AddrPortFrom(addrFromNetstackIP(reqDetails.LocalAddress), reqDetails.LocalPort)

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
