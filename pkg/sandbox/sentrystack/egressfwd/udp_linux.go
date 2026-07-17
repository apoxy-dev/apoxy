// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package egressfwd

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
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	sentrystack "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
)

// ErrNonDNSUDPDenied is returned by routedUDPDialer.DialUDP when a worker
// attempts UDP egress to anything other than :53. Worker-side UDP policy is not
// wired yet; until it is, non-DNS UDP fails closed so a worker can't bypass the
// egress policy / SSRF backstop (which only see the TCP bridge) by switching
// protocols. Stable error value — tests rely on it.
var ErrNonDNSUDPDenied = errors.New("non-DNS UDP egress denied (no UDP policy plumbing yet)")

const (
	// udpFlowTableCap bounds the per-stack 4-tuple session table. Two orders of
	// magnitude above any realistic concurrent UDP flow count per sandbox; the
	// cap exists only so a misbehaving worker can't grow the map unboundedly via
	// spoofed 4-tuples.
	udpFlowTableCap = 4096

	udpIdleTimeout = 30 * time.Second

	// udpSiblingWait bounds how long a late-arriving sibling on the same 4-tuple
	// waits for the creator goroutine to publish its upstream conn. Covers an
	// upstream dial under load without pinning a handler goroutine on a stuck
	// dial.
	udpSiblingWait = 2 * time.Second

	// udpDialTimeout bounds the upstream resolver dial. UDP DialContext does no
	// handshake so this is effectively instant in practice, but a bound keeps a
	// pathological resolver address from stalling a flow goroutine before the
	// idle timer would reap it.
	udpDialTimeout = 5 * time.Second

	// dnsPort is the well-known DNS port. The routed dialer branches on dst port
	// == 53 to dial the resident's resolvers (from InitStr.DNSResolvers) instead
	// of the original (sandbox-visible, gateway-IP) dst.
	dnsPort = 53
)

// udpDialFunc is the upstream-dial path used by the UDP forwarder. Mirrors the
// TCP bridgeDialer but for UDP — receives the original src + dst so the
// implementation can branch on dst port (DNS) and route to the right upstream.
type udpDialFunc func(ctx context.Context, src, dst netip.AddrPort) (net.Conn, error)

var udpBuffPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

// udpFlowKey is the 4-tuple used by the per-flow session table. Keyed on tcpip
// addresses directly so insertion is allocation-free.
type udpFlowKey struct {
	rAddr tcpip.Address
	rPort uint16
	lAddr tcpip.Address
	lPort uint16
}

func udpFlowKeyFromID(id stack.TransportEndpointID) udpFlowKey {
	return udpFlowKey{
		rAddr: id.RemoteAddress,
		rPort: id.RemotePort,
		lAddr: id.LocalAddress,
		lPort: id.LocalPort,
	}
}

// udpFlow is the per-(4-tuple) session state. The creator goroutine (runUDPFlow)
// assigns upConn + extend, then closes ready; siblings that lost the
// table-insert race block on ready and then write payload directly to upConn.
// The channel close acts as the happens-before barrier for those reads.
//
// Multiple goroutines may write to upConn concurrently (the creator's down→up
// copy loop and any number of fast-path injectors). Safe because UDP datagram
// writes are atomic at the sendmsg(2) level.
type udpFlow struct {
	upConn net.Conn
	extend func()
	ready  chan struct{}
}

type udpFlowTable struct {
	mu    sync.Mutex
	flows map[udpFlowKey]*udpFlow
}

func newUDPFlowTable() *udpFlowTable {
	return &udpFlowTable{flows: make(map[udpFlowKey]*udpFlow)}
}

// getOrInsert returns:
//   - (flow, true)  → newly inserted; caller is the creator.
//   - (flow, false) → existing flow; caller is a late sibling.
//   - (nil,  false) → table at cap; caller should drop the packet.
func (t *udpFlowTable) getOrInsert(key udpFlowKey) (*udpFlow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if f, ok := t.flows[key]; ok {
		return f, false
	}
	if len(t.flows) >= udpFlowTableCap {
		return nil, false
	}
	f := &udpFlow{ready: make(chan struct{})}
	t.flows[key] = f
	return f, true
}

func (t *udpFlowTable) remove(key udpFlowKey, f *udpFlow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.flows[key]; ok && cur == f {
		delete(t.flows, key)
	}
}

// installUDPForwarder registers a per-flow UDP forwarder on the stack. Unlike
// gVisor's stock udp.NewForwarder, this handler coalesces packets that arrive on
// the same 4-tuple within the dispatch window (canonical case: musl's parallel
// A+AAAA queries from the same source port) into a single upstream session — the
// second packet joins the first's flow via direct upConn.Write rather than
// racing CreateEndpoint and losing to ErrPortInUse.
//
// cache is optional; when non-nil, DNS (dst port :53) flows feed every upstream
// response payload into IngestResponse before forwarding it down to the sandbox,
// so the TCP forwarder can later resolve dst IP → qname for the egress preamble
// dstName.
func installUDPForwarder(ts *stack.Stack, dial udpDialFunc, cache *dnsCache) {
	table := newUDPFlowTable()
	ts.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("UDP forwarder handler panicked",
					"recover", r, "stack", string(debug.Stack()), "id", fmt.Sprintf("%+v", id))
			}
		}()
		key := udpFlowKeyFromID(id)
		flow, created := table.getOrInsert(key)
		if flow == nil {
			slog.Warn("UDP flow table full; dropping packet", "cap", udpFlowTableCap)
			return true
		}
		if !created {
			return injectSiblingPacket(flow, pkt)
		}
		// CRITICAL: pkt.Clone() must happen SYNCHRONOUSLY before the handler
		// returns. The transport demux DecRef's the original pkt after the
		// handler returns true; calling Clone() inside the spawned goroutine
		// races the pool returning the pkt and zeroing its fields
		// (NetworkProtocolNumber goes to 0, which then panics with "invalid
		// protocol number = 0" in udp.ForwarderRequest.CreateEndpoint).
		clonedPkt := pkt.Clone()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("UDP forwarder goroutine panicked",
						"recover", r, "stack", string(debug.Stack()))
				}
			}()
			runUDPFlow(context.Background(), ts, dial, table, key, flow, id, clonedPkt, cache)
		}()
		return true
	})
}

// injectSiblingPacket delivers a late-arriving packet on an in-flight flow's
// 4-tuple directly to the upstream conn, bypassing CreateEndpoint. Blocks
// briefly on the creator's ready signal.
func injectSiblingPacket(flow *udpFlow, pkt *stack.PacketBuffer) bool {
	select {
	case <-flow.ready:
	case <-time.After(udpSiblingWait):
		return true
	}
	if flow.upConn == nil {
		return true
	}
	payload := pkt.Data().AsRange().ToSlice()
	if len(payload) == 0 {
		return true
	}
	if _, err := flow.upConn.Write(payload); err != nil {
		return true
	}
	flow.extend()
	return true
}

func runUDPFlow(
	ctx context.Context,
	ts *stack.Stack,
	dial udpDialFunc,
	table *udpFlowTable,
	key udpFlowKey,
	flow *udpFlow,
	id stack.TransportEndpointID,
	pkt *stack.PacketBuffer,
	cache *dnsCache,
) {
	srcAddrPort := netip.AddrPortFrom(unmap4in6(addrFromTcpip(id.RemoteAddress)), id.RemotePort)
	dstAddrPort := netip.AddrPortFrom(unmap4in6(addrFromTcpip(id.LocalAddress)), id.LocalPort)

	logger := slog.With("src", srcAddrPort.String(), "dst", dstAddrPort.String())
	logger.Debug("Forwarding UDP session")

	// Remove from the table first, then close the endpoint, so a sibling packet
	// arriving in the tear-down window either finds the flow gone (and starts a
	// fresh flow) or finds it but discovers upConn closed on Write. Either is
	// correct.
	defer table.remove(key, flow)

	sCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wq waiter.Queue
	req := udp.NewForwarderRequest(ts, id, pkt)
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		if _, isPortInUse := tcpipErr.(*tcpip.ErrPortInUse); isPortInUse {
			logger.Debug("Skipping duplicate UDP flow", "error", tcpipErr.String())
		} else {
			logger.Warn("Failed to create UDP endpoint", "error", tcpipErr.String())
		}
		close(flow.ready)
		return
	}

	downConn := gonet.NewUDPConn(&wq, ep)
	upConn, err := dial(sCtx, srcAddrPort, dstAddrPort)
	if err != nil {
		// The dial site emits its own Warn for the deny so we don't double-log;
		// everything else is a real upstream failure.
		if errors.Is(err, ErrNonDNSUDPDenied) {
			logger.Debug("Non-DNS UDP denied", "error", err)
		} else {
			logger.Warn("Failed to dial UDP upstream", "error", err)
		}
		downConn.Close()
		close(flow.ready)
		return
	}

	timer := time.AfterFunc(udpIdleTimeout, func() {
		logger.Debug("UDP idle timeout reached")
		cancel()
		downConn.Close()
		upConn.Close()
	})
	extend := func() { timer.Reset(udpIdleTimeout) }

	// Publish for the sibling fast path. Assignment must precede the close so the
	// channel close acts as a happens-before barrier for sibling reads of upConn
	// / extend.
	flow.upConn = upConn
	flow.extend = extend
	close(flow.ready)

	// DNS up→down observer: ingest every response payload into the cache before
	// forwarding it back to the sandbox so the TCP forwarder can resolve IP →
	// qname for the egress preamble dstName. Only the response direction (upConn
	// → downConn) is observed; the request direction needs no inspection.
	var upDownObserve func([]byte)
	if cache != nil && id.LocalPort == dnsPort {
		upDownObserve = cache.IngestResponse
	}

	g, copyCtx := errgroup.WithContext(sCtx)
	g.Go(func() error {
		return copyUDPPackets(copyCtx, downConn, upConn, extend, nil)
	})
	g.Go(func() error {
		return copyUDPPackets(copyCtx, upConn, downConn, extend, upDownObserve)
	})

	if err := g.Wait(); err != nil {
		logger.Debug("UDP copy ended", "error", err)
	}

	timer.Stop()
	downConn.Close()
	upConn.Close()
	logger.Debug("UDP forwarding complete")
}

// copyUDPPackets pipes datagrams from src to dst, calling extend after each
// successful forward to push the idle timer. observe (when non-nil) is called
// with the payload before dst.Write so the DNS path can ingest responses without
// forking the copy loop.
func copyUDPPackets(ctx context.Context, src, dst net.Conn, extend func(), observe func([]byte)) error {
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
					return nil
				}
				return err
			}
			if observe != nil {
				observe(pkt[:n])
			}
			if _, err := dst.Write(pkt[:n]); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			extend()
		}
	}
}

// unixResolverScheme prefixes a DNSResolvers entry naming the resident's
// unixgram DNS socket ("unix://<name>"); an "@"-prefixed name is a Linux
// abstract-namespace socket. Abstract names live in the network namespace —
// which the Sentry shares with the host pod — not the filesystem, so they
// stay dialable from the chrooted Sentry where a filesystem path would not
// be.
const unixResolverScheme = "unix://"

// unixDialSeq disambiguates concurrent unixgram client sockets within one
// Sentry process (the name below also embeds the pid for cross-process
// uniqueness in the shared pod netns).
var unixDialSeq atomic.Uint64

// dialUnixgram dials the resolver's unixgram socket with an explicitly bound
// unique abstract local address. The bind is load-bearing: Linux does NOT
// autobind a unix datagram socket on connect(2) (autobind only triggers under
// SO_PASSCRED), so an unbound client is anonymous and the resolver has no
// address to send replies to.
func dialUnixgram(sock string) (net.Conn, error) {
	laddr := &net.UnixAddr{
		Name: fmt.Sprintf("@apoxy-dnsc-%d-%d", os.Getpid(), unixDialSeq.Add(1)),
		Net:  "unixgram",
	}
	return net.DialUnix("unixgram", laddr, &net.UnixAddr{Name: sock, Net: "unixgram"})
}

// routedUDPDialer is the Sentry-side UDP dialer. Branches on dst port — :53
// dials the resident's resolver (from InitStr); everything else fails
// closed.
type routedUDPDialer struct {
	// resolverSock, when set, is the unixgram socket name of the resident's
	// DNS listener and takes precedence over resolvers.
	resolverSock string
	resolvers    []netip.AddrPort
	fallback     *net.Dialer
}

// DialUDP implements udpDialFunc. Rewrites a :53 dst to the configured
// resolver; anything else fails closed with ErrNonDNSUDPDenied (worker-side
// UDP policy is not wired yet — see ErrNonDNSUDPDenied). A :53 flow with no
// configured resolver also fails closed rather than dialing the
// sandbox-visible gateway IP through the host netns, which would loop or leak.
func (d *routedUDPDialer) DialUDP(ctx context.Context, src, dst netip.AddrPort) (net.Conn, error) {
	if dst.Port() != dnsPort {
		slog.Warn("Denied non-DNS UDP egress", "src", src.String(), "dst", dst.String())
		return nil, ErrNonDNSUDPDenied
	}
	dialCtx, cancel := context.WithTimeout(ctx, udpDialTimeout)
	defer cancel()
	if d.resolverSock != "" {
		return dialUnixgram(d.resolverSock)
	}
	if len(d.resolvers) == 0 {
		slog.Warn("Denied DNS egress: no resolver configured", "src", src.String(), "dst", dst.String())
		return nil, ErrNonDNSUDPDenied
	}
	// Stable resolver selection: first entry wins. The resident supplies the
	// resolver list; failover across the list would need a richer dialer, so a
	// worker that cares drives multi-resolver lookup itself.
	return d.fallback.DialContext(dialCtx, "udp", d.resolvers[0].String())
}

// ResolverSocket returns the resident's unixgram DNS socket name, or "" if the
// resolvers are ip:port only. The TCP forwarder reads it to bridge the guest's
// TCP:53 fallback (truncated-answer retries) to the same resolver.
func (d *routedUDPDialer) ResolverSocket() string {
	return d.resolverSock
}

// newRoutedUDPDialer builds the UDP dialer from InitStr.DNSResolvers. Each
// entry is either "unix://<socket>" (the resident's unixgram DNS listener;
// first one wins) or "ip:port"; entries that parse as neither are skipped. An
// empty result means DNS is denied (see DialUDP); non-DNS UDP is denied
// unconditionally regardless of the list.
func newRoutedUDPDialer(init *sentrystack.InitStr) *routedUDPDialer {
	d := &routedUDPDialer{fallback: &net.Dialer{}}
	for _, s := range init.DNSResolvers {
		if sock, ok := strings.CutPrefix(s, unixResolverScheme); ok && sock != "" {
			if d.resolverSock == "" {
				d.resolverSock = sock
			}
			continue
		}
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			slog.Warn("Skipping malformed DNS resolver", "resolver", s, "error", err)
			continue
		}
		d.resolvers = append(d.resolvers, ap)
	}
	return d
}
