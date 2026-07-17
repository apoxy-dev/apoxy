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
// lo+eth0, it registers the outbound forwarders. It arms two independent data
// paths, each gated on its own InitStr field so a resident can enable either
// without the other:
//
//   - TCP egress (init.EgressHostAddr): a catch-all TCP forwarder that bridges
//     every outbound stream to the host egress endpoint. The Sentry stays
//     policy-dumb; the host bridge owns policy + gateway-vs-direct selection.
//   - DNS (init.DNSResolvers): a UDP:53 forwarder that rewrites the worker's
//     query to a configured resolver and dials it from the host netns. Its
//     responses feed a per-sandbox IP→name cache the TCP dialer reads to
//     attribute a flow to the hostname the worker resolved it from (dstName).
//
// With neither field set, outbound stays fail-closed: the core RSTs the
// unhandled SYN / UDP datagram rather than silently direct-dialing through the
// host netns.
func InstallEgress(s *sentrystack.Stack, init *sentrystack.InitStr) {
	ts := s.TCPIPStack()

	// One per-sandbox DNS-answer cache, shared by the two forwarders: the UDP
	// forwarder writes it on :53 responses, the TCP dialer reads it to recover
	// the qname for a resolved dst IP. nil when DNS is not armed.
	var (
		cache        *dnsCache
		resolverSock string
	)
	if len(init.DNSResolvers) > 0 {
		cache = newDNSCache()
		udpDial := newRoutedUDPDialer(init)
		resolverSock = udpDial.ResolverSocket()
		installUDPForwarder(ts, udpDial.DialUDP, cache)
		slog.Debug("DNS forwarder installed", "sandbox_id", init.SandboxID, "resolvers", init.DNSResolvers)
	} else {
		slog.Debug("DNS forwarder not installed; no DNSResolvers", "sandbox_id", init.SandboxID)
	}

	if init.EgressHostAddr == "" {
		slog.Debug("Egress forwarder not installed; no EgressHostAddr", "sandbox_id", init.SandboxID)
		return
	}
	d := &bridgeDialer{egressHostAddr: init.EgressHostAddr, cache: cache}
	// The TCP forwarder catches ALL outbound streams. A guest DNS-over-TCP
	// fallback (dst :53, e.g. after a truncated UDP answer) is bridged to the
	// resident resolver instead of the egress bridge — otherwise it dials the
	// gateway IP and the host bridge SSRF-denies it as private, permanently
	// breaking resolution of any large-answer name.
	h := &tcpHandler{dial: d.dial, resolverSock: resolverSock, cache: cache}
	fwd := tcp.NewForwarder(ts, 0, tcpForwarderMaxInFlight, h.handle)
	ts.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	slog.Debug("Egress forwarder installed", "sandbox_id", init.SandboxID, "bridge", init.EgressHostAddr)
}

// bridgeDialer dials the host egress bridge and announces the sandbox-visible
// (src, dst) tuple — plus the resolved hostname when known — over the preamble,
// so the bridge can recover the real destination its shared socket can't learn
// from the 5-tuple and enforce hostname-based egress policy.
type bridgeDialer struct {
	egressHostAddr string
	// cache is the shared DNS-answer cache (may be nil when DNS is not armed):
	// on connect it maps the resolved dst IP back to the qname the worker asked
	// for, which rides the preamble as dstName.
	cache    *dnsCache
	fallback net.Dialer
}

// dial connects to the host bridge and writes the egress preamble. The returned
// conn is positioned for the raw stream to be spliced onto it.
func (d *bridgeDialer) dial(ctx context.Context, src, dst netip.AddrPort) (net.Conn, error) {
	conn, err := d.fallback.DialContext(ctx, "tcp", d.egressHostAddr)
	if err != nil {
		return nil, fmt.Errorf("dial egress bridge %s: %w", d.egressHostAddr, err)
	}
	// Attribute the flow to the hostname the worker resolved dst from, if the
	// DNS forwarder cached it. Empty for a literal-IP flow or a cache miss; the
	// host bridge then matches CIDR / allow-all rules only.
	var dstName string
	if d.cache != nil {
		dstName = d.cache.Lookup(dst.Addr())
	}
	if err := egresswire.WriteEgressPreamble(conn, src, dst, dstName); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialFunc is the upstream-dial path: given the original sandbox-visible src+dst
// it returns a connection the guest stream is spliced onto.
type dialFunc func(ctx context.Context, src, dst netip.AddrPort) (net.Conn, error)

// tcpHandler is the tcp.NewForwarder callback. Each accepted SYN spawns a
// goroutine that creates the sandbox-side endpoint and either bridges a
// DNS-over-TCP fallback to the resident resolver (dst :53) or splices the
// stream to the host egress bridge (everything else).
type tcpHandler struct {
	dial dialFunc
	// resolverSock, when set, is the resident's unixgram DNS socket; a dst-:53
	// connection is bridged to it instead of the egress bridge.
	resolverSock string
	cache        *dnsCache
}

func (h *tcpHandler) handle(req *tcp.ForwarderRequest) {
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
		h.handleTCP(req, src, dst, logger)
	}()
}

func (h *tcpHandler) handleTCP(req *tcp.ForwarderRequest, src, dst netip.AddrPort, logger *slog.Logger) {
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

	// DNS-over-TCP fallback: bridge to the resident resolver, never the egress
	// bridge. A truncated UDP answer makes the stub retry the query over TCP:53;
	// routing it here keeps it inside the resolver plane.
	if dst.Port() == dnsPort && h.resolverSock != "" {
		err := serveDNSOverTCP(local, h.resolverSock, h.cache)
		logDNSOverTCPExit(logger, err)
		req.Complete(err != nil && !isBenignClose(err)) // RST only on a real error
		return
	}

	remote, err := h.dial(ctx, src, dst)
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
