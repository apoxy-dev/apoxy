// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
	"github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack/egresswire"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// egressDialTimeout bounds a single upstream (direct) dial so a black-holed
// destination can't pin a bridge goroutine indefinitely.
const egressDialTimeout = 10 * time.Second

// egressStateLookup is the read seam the bridge consumes: the egress core's
// per-sandbox recorded state (what the config plane pushed). *egressCore
// satisfies it via LookupEgressState.
type egressStateLookup func(id sandbox.SandboxID) (EgressState, bool)

// egressBridge is the host side of the compute egress data path — the
// per-resident counterpart to the in-Sentry forwarder (egressfwd). The Sentry
// stays policy-dumb: it tunnels every outbound flow here over a loopback TCP
// socket (the resident's EgressHostAddr), carrying the real (src,dst) in the
// preamble. The bridge owns ALL policy: it resolves the resident's recorded
// egress state, merges it resident-wide (MVP), rejects worker-local targets
// (SSRF), enforces the merged allow policy, and either direct-dials the
// destination or (gateway path, follow-up) routes via an EgressGateway. A
// denied or unroutable flow is dropped (the guest sees a connection failure),
// so egress is fail-closed.
//
// One bridge per resident sandbox: it captures its resident's SandboxID, so
// unlike clrk's shared bridge it needs no SandboxID in the wire framing.
type egressBridge struct {
	ln     net.Listener
	id     sandbox.SandboxID
	lookup egressStateLookup
	filter *localDstFilter
	log    *slog.Logger
	// dial opens the upstream (direct) connection; a seam so tests can inject a
	// fake upstream without a reachable non-local destination. Defaults to
	// dialDirect.
	dial func(network, addr string) (net.Conn, error)

	// ctx is cancelled by close() on resident teardown. In-flight splices watch
	// it so a half-closed-idle flow is reaped promptly instead of pinning its
	// goroutine + fds until the guest conn happens to close.
	ctx    context.Context
	cancel context.CancelFunc

	// cache memoizes the merged policy for a config generation so the
	// per-Service planes aren't re-merged on every connection. Generation is
	// monotonic and a given generation always maps to the same recorded state
	// (applyEgress is idempotent), so it is a sound cache key.
	mu       sync.Mutex
	cacheSet bool
	cacheGen uint64
	cachePol *sandbox.Policy
	cacheBk  []sandbox.BackendListener
}

// startEgressBridge binds a loopback TCP listener for a resident's egress and
// starts serving. The returned addr is what the resident's Spec.Egress
// carries as EgressHostAddr; the Sentry (sharing the host net namespace) dials
// it. The listener MUST be up before the resident starts so the forwarder's
// first dial lands.
//
// overlayAllow, when non-nil, reports whether a dst belongs to the resident's
// own project overlay endpoints (Apoxy VPC /96s), carving them out of the SSRF
// backstop so a worker can reach its project's tunnel/VPC endpoints; nil when
// the resident has no overlay, in which case all private/ULA space stays denied.
func startEgressBridge(id sandbox.SandboxID, lookup egressStateLookup, overlayAllow func(netip.Addr) bool) (*egressBridge, error) {
	if lookup == nil {
		return nil, fmt.Errorf("egress bridge requires a state lookup")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("binding egress bridge listener: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &egressBridge{
		ln:     ln,
		id:     id,
		lookup: lookup,
		filter: newLocalDstFilter(overlayAllow),
		log:    slog.With("component", "egress-bridge", "sandbox.id", string(id)),
		dial:   dialDirect,
		ctx:    ctx,
		cancel: cancel,
	}
	go b.serve()
	return b, nil
}

// dialDirect is the production upstream dialer: a plain TCP dial with a bounded
// connect timeout.
func dialDirect(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, egressDialTimeout)
}

// addr is the loopback listen address handed to the resident as EgressHostAddr.
func (b *egressBridge) addr() string { return b.ln.Addr().String() }

// close stops accepting new flows and cancels the bridge context so in-flight
// splices unwind promptly (rather than waiting for each guest conn to close on
// resident teardown).
func (b *egressBridge) close() error {
	if b == nil {
		return nil
	}
	if b.cancel != nil {
		b.cancel()
	}
	return b.ln.Close()
}

// serve accepts bridged flows until the listener is closed. A transient accept
// error (e.g. fd exhaustion, EMFILE/ENFILE) must NOT kill the loop: that would
// silently and permanently wedge the resident's egress until the sandbox is
// recreated. Only a closed listener (teardown) ends serve; everything else
// backs off and retries, mirroring net/http.Server.Serve.
func (b *egressBridge) serve() {
	var backoff time.Duration
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // listener closed on resident teardown
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else {
				backoff *= 2
			}
			if max := time.Second; backoff > max {
				backoff = max
			}
			b.log.Warn("Transient egress accept error; backing off and retrying",
				"error", err, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-b.ctx.Done():
				return
			}
			continue
		}
		backoff = 0
		go b.handleConn(conn)
	}
}

// handleConn mediates one outbound flow: preamble -> SSRF -> policy -> backend
// selection -> verdict -> dial -> splice. Every rejection path answers with a
// deny verdict (or, for a malformed preamble, a bare close — the forwarder
// fails closed on any verdict read error) so the forwarder can refuse the
// guest's SYN with an RST without ever allocating a netstack endpoint.
func (b *egressBridge) handleConn(conn net.Conn) {
	defer conn.Close()

	// The bufio.Reader may buffer guest bytes past the preamble; splice from it
	// (not conn) so nothing the guest already sent is dropped.
	r := bufio.NewReader(conn)
	src, dst, dstName, err := egresswire.ReadEgressPreamble(r)
	if err != nil {
		b.log.Warn("Rejected egress flow with a malformed preamble", "error", err)
		return
	}
	log := b.log.With("src", src.String(), "dst", dst.String())
	if dstName != "" {
		log = log.With("dst.name", dstName)
	}

	deny := func() { _ = egresswire.WriteEgressVerdict(conn, false) }

	// SSRF: the guest must never reach the worker/host itself through the
	// bridge (loopback, the host's own interface IPs, link-local, etc.).
	if reason := b.filter.deny(dst); reason != "" {
		log.Warn("Denied egress to a worker-local destination", "reason", reason)
		deny()
		return
	}

	st, ok := b.lookup(b.id)
	if !ok {
		log.Warn("Denied egress: no recorded egress state for resident")
		deny()
		return
	}
	policy, backends := b.resolvePolicy(st)

	// dstName is the hostname the worker resolved dst from (bound by the Sentry
	// DNS forwarder), or "" for a literal-IP flow or a DNS-cache miss.
	// Hostname-based rules match on it; CIDR rules and allow-all match regardless.
	if !policy.Allow(dst, "TCP", dstName) {
		log.Warn("Denied egress by policy")
		deny()
		return
	}

	if backend := sandbox.PickBackend(backends, dst.Port()); backend != nil {
		// Routing through an EgressGateway (Envoy MITM) requires the enriched
		// PROXY-v2 identity frame the gateway expects; that path is the next
		// increment. Fail closed rather than dial the gateway without it.
		log.Warn("Denied egress: gateway routing not yet implemented",
			"backend", backend.Name, "backend.addr", backend.Addr)
		deny()
		return
	}

	// The verdict is the policy decision, sent before the upstream dial so the
	// guest's handshake completes without waiting on a (possibly slow) remote
	// connect. An upstream dial failure after an allow verdict surfaces to the
	// guest as an established-then-closed connection, same as any upstream
	// failure mid-flow.
	if err := egresswire.WriteEgressVerdict(conn, true); err != nil {
		log.Warn("Failed to write egress allow verdict", "error", err)
		return
	}

	// Direct dial (the default gateway / no selected backend).
	upstream, err := b.dial("tcp", dst.String())
	if err != nil {
		log.Warn("Egress direct dial failed", "error", err)
		return
	}
	defer upstream.Close()
	log.Debug("Bridged egress flow (direct)")

	// Reap this flow on resident teardown: closing both conns unblocks the
	// splice's blocked io.Copy so a half-closed-idle flow doesn't pin its
	// goroutine + fds until the guest side happens to close. AfterFunc's stop()
	// deregisters the hook on the normal completion path. (We keep the manual
	// half-closing splice rather than contextio.SpliceContext, which cancels the
	// peer direction shortly after either side EOFs and would truncate a
	// half-duplex response.)
	stop := context.AfterFunc(b.ctx, func() {
		_ = conn.Close()
		_ = upstream.Close()
	})
	defer stop()

	spliceConns(conn, r, upstream)
}

// resolvePolicy returns the merged resident-wide policy and backend set for a
// recorded state, memoized by generation.
func (b *egressBridge) resolvePolicy(st EgressState) (*sandbox.Policy, []sandbox.BackendListener) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cacheSet && b.cacheGen == st.Generation {
		return b.cachePol, b.cacheBk
	}
	pol, bk := mergeResidentEgress(st)
	b.cacheSet, b.cacheGen, b.cachePol, b.cacheBk = true, st.Generation, pol, bk
	return pol, bk
}

// mergeResidentEgress collapses a resident's per-Service egress planes into a
// single policy + backend set (the resident-wide MVP). A flow is allowed if
// ANY Service would allow it, so:
//   - a Service with a nil policy (the implicit default gateway = allow-all)
//     or a non-deny default makes the whole resident allow-all (nil policy) and
//     direct: no backends, because the resident's effective posture is
//     allow-direct and the bridge can't attribute a flow to a specific Service
//     (see LIMITATION). Returning a sibling's gateway backend here would force
//     the not-yet-implemented gateway path — which fail-closes — and so break a
//     working direct Service the moment an unrelated gateway-routed Service
//     appears in the same project;
//   - otherwise every Service is deny-default, and the merge is deny-default
//     over the UNION of their rules AND the union of their backends (a
//     deny-default resident routes matching flows through the selected gateway).
//
// Empty state (no config pushed yet) merges to deny-all, so egress stays
// fail-closed until the config plane pushes the resident's Services.
//
// LIMITATION (stated loudly): this is a same-project relaxation. Within one
// resident, a Service that set a deny-all policy can still egress to a
// destination a sibling Service allows, because the bridge sees only the
// resident (SandboxID), not which Service opened the flow. Per-Service
// fidelity (honoring each Service's own policy AND routing its flows through its
// own gateway) is the fast follow-up; it is NOT a cross-tenant hole (residents
// are per project).
func mergeResidentEgress(st EgressState) (*sandbox.Policy, []sandbox.BackendListener) {
	var backends []sandbox.BackendListener
	var rules []sandbox.Rule
	allowAll := false
	for _, se := range st.Services {
		// A nil policy is allow-all; a non-deny default also allows everything
		// (Policy.Allow returns !DefaultDeny when no rule matches).
		if se.Policy == nil || !se.Policy.DefaultDeny {
			allowAll = true
			continue
		}
		rules = append(rules, se.Policy.Rules...)
		backends = append(backends, se.Backends...)
	}
	if allowAll {
		// Allow-direct; suppress backends (see doc) so no sibling gateway forces
		// the gateway path for the whole resident.
		return nil, nil
	}
	return &sandbox.Policy{DefaultDeny: true, Rules: rules}, backends
}

// spliceConns copies bidirectionally between the guest conn (read via
// guestReader, which carries any bytes buffered past the preamble) and the
// upstream, half-closing each write side on EOF so a one-way shutdown
// propagates without truncating the other direction.
func spliceConns(guest net.Conn, guestReader io.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, guestReader)
		halfCloseWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(guest, upstream)
		halfCloseWrite(guest)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// halfCloseWrite sends a FIN on conn's write side if it supports half-close
// (TCP does), signalling EOF to the peer while leaving reads open.
func halfCloseWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// cgnatPrefix is RFC 6598 carrier-grade-NAT space (100.64.0.0/10). Some
// Kubernetes CNIs (and cloud fabrics) use it for pod/service addressing, so it
// is treated as internal alongside the RFC1918 / ULA ranges IsPrivate covers.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// localDstFilter rejects sandbox-supplied destinations that point back at the
// worker/host itself OR at cluster-internal / private space. It is the SSRF
// backstop for the allow-all default gateway: a worker with no egress block
// resolves an allow-all policy, so without this a tenant fetch() could reach the
// kube-apiserver ClusterIP, sibling pods, internal databases, or the cloud IMDS
// (169.254.169.254). Ported from clrk's egress bridge and hardened for the
// multi-tenant cluster: private/ULA/CGNAT ranges are denied as a hard backstop
// (an explicitly-configured EgressGateway is the intended path to a private
// endpoint, a follow-up once the gateway data plane exists). The compute
// forwarder has no IMDS bridge yet, so link-local is blanket-denied here.
type localDstFilter struct {
	// overlayAllow, when non-nil, reports whether a dst belongs to the resident's
	// OWN project overlay endpoints (the Apoxy VPC /96s this project's tunnel
	// endpoints allocate). Such a dst is a legitimate egress target and is
	// allowed BEFORE the blanket private/ULA deny below, so a worker can reach
	// its own project's overlay while every other private range stays denied.
	//
	// It is a membership predicate rather than a single prefix on purpose: every
	// project's endpoints share the "default" network /72, so a /72-wide carve-out
	// would admit other tenants' endpoints. The predicate (supplied per-tenant by
	// the manager, backed by the project-filtered endpoint index) admits only
	// this project's actual /96s and is checked live, so it is both tenant-scoped
	// and rebinding-safe — a ULA that a malicious upstream AAAA claims but that no
	// endpoint of this project allocates is not admitted. nil when the resident
	// has no overlay: then all ULA/private space is denied as before.
	overlayAllow func(netip.Addr) bool
	localIPs     map[netip.Addr]struct{}
}

// newLocalDstFilter snapshots the host's interface IPs once and records the
// resident's overlay carve-out. Interface enumeration failure degrades to
// categorical-only filtering (loopback, link-local, unspecified, multicast)
// rather than failing the resident: those checks need no enumeration, and losing
// the own-IP set is safer than taking the whole resident down over a transient
// netlink error.
func newLocalDstFilter(overlayAllow func(netip.Addr) bool) *localDstFilter {
	ips := make(map[netip.Addr]struct{})
	ifs, err := net.Interfaces()
	if err != nil {
		slog.Warn("Egress SSRF filter: interface enumeration failed; own-IP denial disabled", "error", err)
		return &localDstFilter{overlayAllow: overlayAllow, localIPs: ips}
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if na, ok := netip.AddrFromSlice(ip); ok {
				ips[na.Unmap()] = struct{}{}
			}
		}
	}
	return &localDstFilter{overlayAllow: overlayAllow, localIPs: ips}
}

// deny returns a non-empty categorical reason when dst is a destination that
// must not be reachable via the bridge (worker-local, cluster-internal, or
// otherwise private), or "" to allow. It is evaluated on the resolved dst.Addr()
// the forwarder observed the connect() to, so it catches internal IPs whether
// the worker used a literal or (once DNS lands) a name that resolved to one.
func (f *localDstFilter) deny(dst netip.AddrPort) string {
	if f == nil {
		return ""
	}
	addr := dst.Addr().Unmap()
	// First classify the destination. The categorical denies below are
	// absolute — loopback, link-local (IMDS), the pod's own interface IPs, etc.
	// must be refused even under an allow-all policy AND even if a bogus
	// overlay carve-out somehow covered them.
	reason := ""
	switch {
	case addr.IsLoopback():
		reason = "loopback" // 127.0.0.0/8, ::1
	case addr.IsUnspecified():
		reason = "unspecified" // 0.0.0.0, ::
	case addr.IsLinkLocalUnicast():
		reason = "link-local" // 169.254.0.0/16 (incl. IMDS), fe80::/10
	case addr.IsLinkLocalMulticast():
		reason = "link-local-multicast" // 224.0.0.0/24, ff02::/16
	case addr.IsInterfaceLocalMulticast():
		reason = "interface-local-multicast" // ff01::/16
	case addr.IsMulticast():
		reason = "multicast" // 224.0.0.0/4, ff00::/8
	case addr.IsPrivate():
		reason = "private" // RFC1918 (10/8, 172.16/12, 192.168/16) + IPv6 ULA fc00::/7
	case cgnatPrefix.Contains(addr):
		reason = "cgnat" // RFC6598 100.64.0.0/10 (some k8s pod/service CIDRs)
	default:
		if _, ok := f.localIPs[addr]; ok {
			reason = "worker-local-interface"
		}
	}
	if reason == "" {
		return "" // A public destination: allowed regardless of the carve-out.
	}
	// The destination would be denied. Consult the overlay carve-out LAST, and
	// only for addresses inside the Apoxy VPC overlay prefix: the resident's own
	// project endpoints (VPC /96s) are legitimate targets. overlayAllow admits
	// only this project's actual endpoint /96s (never the shared /72, never
	// another tenant's), checked live and rebinding-safe. Gating on the overlay
	// prefix means the carve-out can only ever relax "private" (ULA) — never
	// loopback, link-local, or the pod's own interfaces — so a malformed
	// (non-overlay) reachable window can't punch a hole in the categorical
	// denies. NOTE: this permits the connect at the policy layer; the direct
	// dial reaches the endpoint via the Geneve overlay routes the co-located
	// backplane maintains in the shared pod netns.
	if tunnet.ULAPrefix().Contains(addr) && f.overlayAllow != nil && f.overlayAllow(addr) {
		return ""
	}
	return reason
}
