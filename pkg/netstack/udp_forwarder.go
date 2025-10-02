package netstack

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/dpeckett/network"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	alog "github.com/apoxy-dev/apoxy/pkg/log"
)

const dnsPort = 8053

var udpBuffPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

// UDPForwarder forwards UDP packets to an upstream network.
func UDPForwarder(ctx context.Context, ipstack *stack.Stack, upstream network.Network) ProtocolHandler {
	udpForwarder := udp.NewForwarder(
		ipstack,
		udpHandler(ctx, upstream),
	)

	return udpForwarder.HandlePacket
}

func copyPackets(ctx context.Context, src, dst net.Conn, once bool, extend func()) error {
	logger := alog.FromContext(ctx)
	logger.Debug("Copying packets...")

	buf := udpBuffPool.Get().(*[]byte)
	pkt := (*buf)[:cap(*buf)]
	defer udpBuffPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, err := src.Read(pkt)
			if err != nil {
				if ctx.Err() != nil {
					return nil // Don't print error if context is canceled.
				}
				logger.Error("Read failed", slog.Any("error", err))
				return err
			}

			if _, err := dst.Write(pkt[:n]); err != nil {
				if ctx.Err() != nil {
					return nil // Don't print error if context is canceled.
				}
				logger.Error("Write failed", slog.Any("error", err))
				return err
			}

			if once {
				logger.Debug("Done copying packets")
				return nil
			}

			extend()
		}
	}
}

func udpHandler(ctx context.Context, upstream network.Network) func(req *udp.ForwarderRequest) {
	return func(req *udp.ForwarderRequest) {
		reqDetails := req.ID()

		srcAddrPort := netip.AddrPortFrom(addrFromNetstackIP(reqDetails.RemoteAddress), reqDetails.RemotePort)
		// Handle 4in6 embedded IPs same as TCP forwarder:
		// - IPv4-mapped IPv6 addresses (::ffff:192.168.1.1) are converted to IPv4
		// - Regular IPv6 addresses left as is (::1)
		dstAddrPort := netip.AddrPortFrom(
			addrFromNetstackIP(reqDetails.LocalAddress).Unmap(),
			reqDetails.LocalPort,
		)

		logger := slog.With(
			slog.String("src", srcAddrPort.String()),
			slog.String("dst", dstAddrPort.String()))

		logger.Debug("Forwarding UDP session")

		go func() {
			sCtx, cancel := context.WithCancel(ctx)

			var wq waiter.Queue
			ep, tcpipErr := req.CreateEndpoint(&wq)
			if tcpipErr != nil {
				logger.Error("Failed to create endpoint", slog.String("error", tcpipErr.String()))
				cancel()
				return
			}

			downConn := gonet.NewUDPConn(&wq, ep)
			upConn, err := upstream.DialContext(sCtx, "udp", dstAddrPort.String())
			if err != nil {
				logger.Error("Failed to dial upstream", slog.Any("error", err))
				cancel()
				downConn.Close()
				return
			}

			idleTimeout := 30 * time.Second
			timer := time.AfterFunc(idleTimeout, func() {
				logger.Debug("Idle timeout reached")
				cancel()
				downConn.Close()
				upConn.Close()
			})
			cleanup := func() {
				cancel()
				downConn.Close()
				upConn.Close()
				timer.Stop()
			}
			extend := func() {
				timer.Reset(idleTimeout)
			}
			// For DNS sessions, send one packet each way and then close immediately.
			once := dstAddrPort.Port() == dnsPort

			g, copyCtx := errgroup.WithContext(sCtx)
			g.Go(func() error {
				logger := logger.With(slog.String("direction", "down"))
				return copyPackets(alog.IntoContext(copyCtx, logger), downConn, upConn, once, extend)
			})
			g.Go(func() error {
				logger := logger.With(slog.String("direction", "up"))
				return copyPackets(alog.IntoContext(copyCtx, logger), upConn, downConn, once, extend)
			})

			if err := g.Wait(); err != nil {
				logger.Error("Failed to copy packets", slog.Any("error", err))
			}
			cleanup()
			logger.Debug("UDP forwarding complete")
		}()
	}
}
