//go:build linux

package sentrystack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"

	"github.com/dpeckett/contextio"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// installControlForwarder wires the resident → host-manager control path: the
// guest→host mirror of the inbound forwarder. A dispatcher worker running inside
// the resident dials listenAddr — an otherwise-unused in-sandbox loopback target
// (e.g. "127.0.0.2:80"), deliberately distinct from the resident's own data
// listener on 127.0.0.1 — to reach the host manager's control HTTP server, from
// which WorkerLoader pulls customer worker definitions. This forwarder runs an
// in-stack TCP listener on listenAddr, accepts each guest connection, and
// splices it to a fresh host net.Dial("tcp", hostAddr) toward the manager's
// control server (a host-loopback TCP listener in the Sentry's own netns).
//
// Two ways this differs from the inbound forwarder:
//
//   - Direction. Inbound accepts on a host AF_UNIX fd and DIALS into the guest
//     stack; control is the reverse — the guest is the client, so the in-stack
//     side is a LISTENER and the host side is the upstream dial.
//   - No fd donation. The Sentry process shares the host net namespace, so it
//     net.Dial("tcp", hostAddr)s the manager's loopback control listener
//     directly; nothing rides cmd.ExtraFiles. That is why control is sealed
//     entirely in the init payload with no InboundFDIndex analogue.
//
// The host side is TCP, not AF_UNIX: the Sentry's seccomp filter
// (pkg/sentry/socket/plugin) only permits socket() for AF_INET/AF_INET6, so a
// host net.Dial("unix", …) from inside the Sentry returns ENOSYS. The egress
// forwarder dials its host upstream the same way (127.0.0.1:<port> TCP).
//
// listenAddr is assigned to its NIC before the listener binds so the bind does
// not hinge on spoofing semantics for an address the core never otherwise
// configures (lo carries 127.0.0.1/8; 127.0.0.2 is in-subnet but not an assigned
// address). The forwarder is resident: the accept loop runs for the stack's
// lifetime and ends when the listener closes at stack teardown.
func (s *Stack) installControlForwarder(listenAddr, hostAddr string) error {
	target, proto, err := parseInboundTarget(listenAddr)
	if err != nil {
		return fmt.Errorf("control forward addr %q: %w", listenAddr, err)
	}

	// Assign the control address so the in-stack listener binds it
	// unconditionally. Non-fatal on error: the address may already be present,
	// or spoofing may let the bind through regardless — ListenTCP below is the
	// authority on whether the control listener can come up.
	prefixLen := 32
	if proto == ipv6.ProtocolNumber {
		prefixLen = 128
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: target.Addr, PrefixLen: prefixLen},
	}
	if addErr := s.tcpipStack().AddProtocolAddress(target.NIC, pa, stack.AddressProperties{}); addErr != nil {
		slog.Debug("Control addr assignment returned (continuing to listen)",
			slog.String("addr", listenAddr), slog.String("error", addErr.String()))
	}

	ln, err := gonet.ListenTCP(s.tcpipStack(), target, proto)
	if err != nil {
		return fmt.Errorf("listening in-stack on control addr %q: %w", listenAddr, err)
	}

	go s.acceptControl(ln, hostAddr)
	return nil
}

// acceptControl is the control accept loop. It exits when the in-stack listener
// is closed (stack teardown); any other Accept error is fatal to the loop and
// logged (a dispatcher retries its control fetch on the next request).
func (s *Stack) acceptControl(ln net.Listener, hostAddr string) {
	for {
		guestConn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("Control listener accept error", slog.Any("error", err))
			return
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Control forwarder goroutine panic",
						slog.Any("recover", r),
						slog.String("stack", string(debug.Stack())))
				}
			}()
			s.handleControl(guestConn, hostAddr)
		}()
	}
}

// handleControl splices one guest-originated control connection to a fresh host
// TCP dial of the manager's control server. Mirror of handleInbound: there the
// host side is the accepted conn and the in-stack dial is the upstream; here the
// in-stack accept is the guest side and the host TCP dial is the upstream.
func (s *Stack) handleControl(guestConn net.Conn, hostAddr string) {
	defer guestConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.With(
		slog.String("guest", guestConn.RemoteAddr().String()),
		slog.String("host_addr", hostAddr),
	)

	hostConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", hostAddr)
	if err != nil {
		// The manager's control server is expected to be listening before the
		// resident is started; surface a dial failure rather than dropping it.
		logger.Warn("Failed to dial host control server", slog.Any("error", err))
		return
	}
	defer hostConn.Close()

	logger.Debug("Splicing control")
	wn, err := contextio.SpliceContext(ctx, guestConn, hostConn, nil)
	if err != nil && !errors.Is(err, context.Canceled) {
		if isBenignClose(err) {
			logger.Debug("Peer closed mid-splice", slog.Any("error", err))
		} else {
			logger.Warn("Control splice error", slog.Any("error", err))
		}
		return
	}
	logger.Debug("Control session closed", slog.Int64("bytes", wn))
}
