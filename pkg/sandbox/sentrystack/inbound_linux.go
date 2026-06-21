//go:build linux

package sentrystack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/dpeckett/contextio"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

// installInboundForwarder wires the host → resident-server ingress path,
// the exact reverse of an egress forwarder. fd is the host AF_UNIX listening
// socket the host handed to the Sentry (PreInit → FilePayload →
// InitStackArgs.FDs); listenAddr is the in-sandbox "ip:port" the resident
// server (workerd, or a test stub) is listening on.
//
// For each connection the host accepts on fd, a goroutine dials listenAddr
// inside the in-Sentry stack and bidirectionally splices the two. The in-stack
// dial reaches the resident listener — not any egress catch-all forwarder an
// embedder installed in doInit — because a bound listening endpoint shadows
// the global TCP transport handler (proven in inbound_demux_test.go).
//
// The forwarder is resident: the accept loop runs for the stack's lifetime.
// There's nothing to unregister beyond closing the listener, which happens
// when the Sentry tears the stack down.
func (s *Stack) installInboundForwarder(fd int, listenAddr string) error {
	target, proto, err := parseInboundTarget(listenAddr)
	if err != nil {
		return fmt.Errorf("inbound listen addr %q: %w", listenAddr, err)
	}

	// The fd is a host AF_UNIX listening socket; net.FileListener adopts it.
	// os.NewFile does not dup, and FileListener dups internally, so close our
	// transient *os.File once the listener owns its own copy.
	f := os.NewFile(uintptr(fd), "clrk-inbound")
	hostLn, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("adopting inbound listener fd %d: %w", fd, err)
	}

	go s.acceptInbound(hostLn, target, proto)
	return nil
}

// acceptInbound is the inbound accept loop. It exits when the host listener
// is closed (stack teardown); any other Accept error is transient and retried
// by continuing the loop after logging.
func (s *Stack) acceptInbound(hostLn net.Listener, target tcpip.FullAddress, proto tcpip.NetworkProtocolNumber) {
	for {
		hostConn, err := hostLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("Inbound listener accept error", slog.Any("error", err))
			return
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Inbound forwarder goroutine panic",
						slog.Any("recover", r),
						slog.String("stack", string(debug.Stack())))
				}
			}()
			s.handleInbound(hostConn, target, proto)
		}()
	}
}

// handleInbound splices one host-originated connection to a fresh in-stack
// dial toward the resident server. Mirror of an egress handler: there, the
// sandbox side is the forwarder-created endpoint and the upstream is a host
// dial; here, the host side is the accepted conn and the "upstream" is the
// in-stack dial into the resident listener.
func (s *Stack) handleInbound(hostConn net.Conn, target tcpip.FullAddress, proto tcpip.NetworkProtocolNumber) {
	defer hostConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.With(
		slog.String("host", hostConn.RemoteAddr().String()),
		slog.String("target", fmt.Sprintf("%s:%d", target.Addr, target.Port)),
	)

	guest, err := gonet.DialContextTCP(ctx, s.tcpipStack(), target, proto)
	if err != nil {
		// ECONNREFUSED here usually means the resident server hasn't
		// finished listen()ing yet — the readiness gate is the host's
		// job (it must not expose the host listener before the server is
		// up). Surface it rather than silently dropping.
		logger.Warn("Failed to dial resident server", slog.Any("error", err))
		return
	}
	defer guest.Close()

	logger.Debug("Splicing inbound")
	wn, err := contextio.SpliceContext(ctx, hostConn, guest, nil)
	if err != nil && !errors.Is(err, context.Canceled) {
		if isBenignClose(err) {
			logger.Debug("Peer closed mid-splice", slog.Any("error", err))
		} else {
			logger.Warn("Inbound splice error", slog.Any("error", err))
		}
		return
	}
	logger.Debug("Inbound session closed", slog.Int64("bytes", wn))
}

// parseInboundTarget converts an in-sandbox "ip:port" listen address into the
// tcpip.FullAddress + network protocol the in-stack dialer needs. Loopback
// addresses route via the lo NIC (always present, even in Phase 1 lo-only
// mode); everything else routes via eth0.
func parseInboundTarget(listenAddr string) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, error) {
	ap, err := netip.ParseAddrPort(listenAddr)
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	addr := ap.Addr()

	full := tcpip.FullAddress{Port: ap.Port()}
	var proto tcpip.NetworkProtocolNumber
	if addr.Is4() {
		full.Addr = tcpip.AddrFrom4(addr.As4())
		proto = ipv4.ProtocolNumber
	} else {
		full.Addr = tcpip.AddrFrom16(addr.As16())
		proto = ipv6.ProtocolNumber
	}
	if addr.IsLoopback() {
		full.NIC = loNICID
	} else {
		full.NIC = eth0NICID
	}
	return full, proto, nil
}

// isBenignClose reports whether err is the ordinary remote-closed-the-connection
// shape that a splice sees when either peer hangs up — a reset or a broken pipe.
// Such closes are expected session ends, logged at debug not warn. Mirrors
// clrk's internal/egress.IsBenignClose; inlined here so the tenant-neutral core
// carries no dependency on the egress wrapper.
func isBenignClose(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}
