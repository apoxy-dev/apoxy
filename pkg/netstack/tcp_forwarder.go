package netstack

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/dpeckett/network"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/apoxy-dev/apoxy/pkg/net/splice"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// ProtocolHandler handles the packets of one transport protocol.
type ProtocolHandler func(stack.TransportEndpointID, *stack.PacketBuffer) bool

// TCPForwarder forwards TCP connections to an upstream network.
func TCPForwarder(ctx context.Context, ipstack *stack.Stack, upstream network.Network) ProtocolHandler {
	tcpForwarder := tcp.NewForwarder(
		ipstack,
		0,     // Receive window. Zero is the default.
		65535, // Most handshakes in progress.
		tcpHandler(ctx, upstream),
	)

	return tcpForwarder.HandlePacket
}

var (
	// nat64Prefix is the well-known prefix of RFC 6052.
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	// attachmentHost is the last 32 bits of a VPC attachment address, ::1 in its /96.
	attachmentHost = netip.AddrFrom4([4]byte{0, 0, 0, 1})
)

// Unmap4in6 returns the IPv4 address in an IPv4-mapped address or in a NAT64 or
// overlay ULA /96 (RFC 6052). It keeps other addresses and VPC attachment addresses.
func Unmap4in6(addr netip.Addr) netip.Addr {
	if !addr.Is6() {
		return addr
	}
	b := addr.As16()
	v4 := netip.AddrFrom4([4]byte(b[12:]))
	switch {
	case addr.Is4In6(), nat64Prefix.Contains(addr):
		return v4
	case tunnet.ULAPrefix().Contains(addr) && v4 != attachmentHost:
		return v4
	}
	return addr
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

			// Dial before the handshake completes, so that a failed dial resets the SYN.
			remote, err := upstream.DialContext(ctx, "tcp", dstAddrPort.String())
			if err != nil {
				logger.Warn("Failed to dial destination", slog.Any("error", err))

				req.Complete(true) // Send RST.
				return
			}
			defer remote.Close()

			logger.Info("Connected to upstream")

			var wq waiter.Queue
			ep, tcpipErr := req.CreateEndpoint(&wq)
			if tcpipErr != nil {
				logger.Warn("Failed to create local endpoint",
					slog.String("error", tcpipErr.String()))

				req.Complete(true) // Send RST.
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
			// Keep-alive finds dead connections.
			ep.SocketOptions().SetKeepAlive(true)

			local := gonet.NewTCPConn(&wq, ep)
			defer local.Close()

			// Start forwarding.
			wn, err := splice.Splice(ctx, local, remote)
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("Failed to forward session", slog.Any("error", err))

				req.Complete(true) // Send RST.
				return
			}
			logger.Info("Connection closed", slog.Int64("bytes_written", wn))

			req.Complete(false) // Send FIN.
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
