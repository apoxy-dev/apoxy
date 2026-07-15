// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package egressfwd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"syscall"

	"github.com/dpeckett/contextio"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	sentrystack "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
	"github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack/egresswire"
)

// tcpForwarderMaxInFlight bounds the half-open TCP forwarder requests gVisor
// queues before dropping new SYNs. Matches clrk's value: high enough that a
// burst of concurrent connects from inside the sandbox isn't RSTed pre-handoff.
const tcpForwarderMaxInFlight = 65535

// InstallEgress is the sentrystack.ForwarderInstaller: after the core wires
// lo+eth0, it registers a catch-all TCP forwarder that bridges every outbound
// stream to the host egress endpoint at init.EgressHostAddr. Registered once at
// Init and lives for the stack's lifetime.
//
// The Sentry stays policy-dumb: it tunnels every flow to the host bridge, which
// owns policy + gateway-vs-direct selection (mirroring clrk). If EgressHostAddr
// is unset the forwarder is not installed, so outbound stays fail-closed (the
// core RSTs the unhandled SYN) rather than silently direct-dialing through the
// host netns.
func InstallEgress(s *sentrystack.Stack, init *sentrystack.InitStr) {
	if init.EgressHostAddr == "" {
		slog.Debug("Egress forwarder not installed; no EgressHostAddr", "sandbox_id", init.SandboxID)
		return
	}
	d := &bridgeDialer{egressHostAddr: init.EgressHostAddr}
	ts := s.TCPIPStack()
	fwd := tcp.NewForwarder(ts, 0, tcpForwarderMaxInFlight, makeTCPHandler(d.dial))
	ts.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	slog.Debug("Egress forwarder installed", "sandbox_id", init.SandboxID, "bridge", init.EgressHostAddr)
}

// bridgeDialer dials the host egress bridge and announces the sandbox-visible
// (src, dst) tuple over the preamble so the bridge can recover the real
// destination its shared socket can't learn from the 5-tuple.
type bridgeDialer struct {
	egressHostAddr string
	fallback       net.Dialer
}

// dial connects to the host bridge and writes the egress preamble. The returned
// conn is positioned for the raw stream to be spliced onto it.
func (d *bridgeDialer) dial(ctx context.Context, src, dst netip.AddrPort) (net.Conn, error) {
	conn, err := d.fallback.DialContext(ctx, "tcp", d.egressHostAddr)
	if err != nil {
		return nil, fmt.Errorf("dial egress bridge %s: %w", d.egressHostAddr, err)
	}
	if err := egresswire.WriteEgressPreamble(conn, src, dst); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialFunc is the upstream-dial path: given the original sandbox-visible src+dst
// it returns a connection the guest stream is spliced onto.
type dialFunc func(ctx context.Context, src, dst netip.AddrPort) (net.Conn, error)

// makeTCPHandler returns the tcp.NewForwarder callback. Each accepted SYN spawns
// a goroutine that creates the sandbox-side endpoint, dials upstream, and
// bidirectionally splices until either side closes.
func makeTCPHandler(dial dialFunc) func(req *tcp.ForwarderRequest) {
	return func(req *tcp.ForwarderRequest) {
		id := req.ID()
		src := netip.AddrPortFrom(unmap4in6(addrFromTcpip(id.RemoteAddress)), id.RemotePort)
		dst := netip.AddrPortFrom(unmap4in6(addrFromTcpip(id.LocalAddress)), id.LocalPort)
		logger := slog.With("src", src.String(), "dst", dst.String())

		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Egress forwarder goroutine panicked",
						"recover", r, "stack", string(debug.Stack()))
				}
			}()
			handleTCP(req, src, dst, dial, logger)
		}()
	}
}

func handleTCP(req *tcp.ForwarderRequest, src, dst netip.AddrPort, dial dialFunc, logger *slog.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wq waiter.Queue
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		logger.Warn("Failed to create sandbox endpoint", "error", tcpipErr.String())
		req.Complete(true) // RST
		return
	}

	// Cancel the splice on TCP HUP from the sandbox side so we don't hold the
	// upstream conn open after the worker half-closes.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	go func() {
		select {
		case <-ctx.Done():
		case <-notifyCh:
			cancel()
		}
	}()

	ep.SocketOptions().SetDelayOption(false) // disable Nagle
	ep.SocketOptions().SetKeepAlive(true)

	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()

	remote, err := dial(ctx, src, dst)
	if err != nil {
		logger.Warn("Failed to dial egress bridge", "error", err)
		req.Complete(true) // RST
		return
	}
	defer remote.Close()

	if _, err := contextio.SpliceContext(ctx, local, remote, nil); err != nil &&
		!errors.Is(err, context.Canceled) && !isBenignClose(err) {
		logger.Warn("Egress splice error", "error", err)
		req.Complete(true) // RST
		return
	}
	req.Complete(false) // FIN
}

// isBenignClose reports whether err is an ordinary peer-close mid-splice rather
// than a real failure worth logging and RSTing the sandbox for. Benign means
// EOF, use-of-closed-conn, or the peer tearing the connection down (broken pipe
// / connection reset) — the normal ways a proxied flow ends.
//
// It must NOT swallow genuine egress-path failures (connection refused, timeout,
// host/network unreachable): those surface a *net.OpError too, so matching any
// *net.OpError (as an earlier version did) hid real failures from operators and
// signalled the guest a clean FIN instead of an RST. Check the specific errnos
// instead.
func isBenignClose(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}

// addrFromTcpip converts a tcpip.Address into a netip.Addr, handling both the
// 4-byte and 16-byte cases without inferring family from length alone.
func addrFromTcpip(a tcpip.Address) netip.Addr {
	switch a.Len() {
	case 4:
		return netip.AddrFrom4(a.As4())
	case 16:
		return netip.AddrFrom16(a.As16())
	default:
		return netip.Addr{}
	}
}

// unmap4in6 collapses ::ffff:0.0.0.0/96 onto native v4; the tcpip stack hands us
// v4-mapped addresses for sockets opened on a v6 endpoint that routed v4.
func unmap4in6(a netip.Addr) netip.Addr {
	if a.Is4In6() {
		return a.Unmap()
	}
	return a
}
