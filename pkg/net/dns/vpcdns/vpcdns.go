// SPDX-License-Identifier: AGPL-3.0-only

// Package vpcdns is the serving core of the Apoxy VPC name plane: a CoreDNS
// plugin that answers, authoritatively, for names bound into a project's VPC
// (tunnel endpoints today, VPC-bound Services later) and passes everything
// else to the next plugin in the chain (typically cache -> upstream).
//
// The core is deliberately split from any data source: it resolves against a
// Snapshot the caller's Source func returns per query, so the same logic
// serves both the backplane's controller-runtime endpoint index and a workerd
// resident's pushed (ApplyDNS) state. Binding tables are per-project and
// small, so the per-query snapshot scan is cheap.
package vpcdns

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const (
	resolveTimeout  = 5 * time.Second
	upstreamTimeout = 2 * time.Second
	maxAnswers      = 10

	// defaultTTL is the answer TTL for bindings that don't set one.
	defaultTTL = 30

	// delegateResolverPort is the port of the DNS resolver co-located with a
	// delegating binding's endpoint: the tunnel node runs its resolver on
	// loopback :8053, reachable through the overlay by embedding 127.0.0.1
	// into the endpoint's /96 (see upstreamHostFromAddr).
	delegateResolverPort = 8053

	// gracePeriod is how long to wait for additional upstream responses after
	// the first successful answer. Prevents slow or dead upstreams from
	// blocking the entire resolution.
	gracePeriod = 200 * time.Millisecond
)

var delegateResolverV4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// Binding is one name bound into the project VPC: the resolvable FQDN, the
// addresses it answers with, and the reachability window those addresses
// grant through the egress SSRF backstop.
type Binding struct {
	// FQDN is the name this binding answers for (no trailing dot).
	FQDN string
	// Addrs are the addresses the name resolves to (answered as A or AAAA by
	// address family).
	Addrs []netip.Addr
	// Delegate forwards sub-names (x.<FQDN>) to a resolver at this binding's
	// addrs instead of answering locally (recursive tunnel resolution).
	Delegate bool
	// TTL for answers in seconds; 0 means defaultTTL.
	TTL uint32
	// Reachable are the prefixes carved out of the egress SSRF backstop for
	// this binding.
	Reachable []netip.Prefix
}

// Snapshot is one consistent view of the name plane: the zones the resolver
// answers authoritatively for and the current binding set. Multiple bindings
// may share an FQDN (one endpoint each); their addrs merge at answer time.
type Snapshot struct {
	Zones    []string
	Bindings []Binding
}

// Reachable reports whether addr falls within any binding's reachable
// prefixes. This is the rebinding-safe membership check backing the egress
// SSRF carve-out: it admits only addresses the project's own bindings
// actually granted — regardless of what any DNS answer claimed.
func (s Snapshot) Reachable(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, b := range s.Bindings {
		for _, p := range b.Reachable {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// Metrics are optional observation hooks; nil funcs are skipped.
type Metrics struct {
	// Query is invoked once per handled query with the outcome:
	// "hit", "recursive", "nxdomain", or "passthrough".
	Query func(outcome string)
	// RecursiveDuration observes one recursive resolution's duration.
	RecursiveDuration func(seconds float64)
	// UpstreamAbandoned counts delegate upstreams abandoned after the grace
	// period.
	UpstreamAbandoned func(n int)
}

// Handler resolves VPC names against the Source's snapshot.
type Handler struct {
	// Source returns the current name-plane snapshot; required.
	Source func() Snapshot
	// QueryUpstream resolves a DNS request against a single delegate upstream
	// address. Nil means the default UDP-with-TCP-fallback exchange against
	// the overlay-embedded resolver (upstreamHostFromAddr); tests override it.
	QueryUpstream func(ctx context.Context, upstream netip.Addr, req *dns.Msg) (*dns.Msg, error)
	// Metrics are the optional observation hooks.
	Metrics Metrics
	// Name labels this handler in plugin errors; defaults to "vpcdns".
	Name string
}

func (h *Handler) name() string {
	if h.Name != "" {
		return h.Name
	}
	return "vpcdns"
}

func (h *Handler) observeQuery(outcome string) {
	if h.Metrics.Query != nil {
		h.Metrics.Query(outcome)
	}
}

// Plugin returns the CoreDNS plugin serving this handler.
func (h *Handler) Plugin(next plugin.Handler) plugin.Handler {
	return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
		code, err := h.serveDNS(ctx, next, w, req)
		if code == dns.RcodeSuccess {
			return code, err
		}
		// If serveDNS returned an authoritative NXDOMAIN (for in-zone names),
		// the response has already been written — don't fall through to the
		// next plugin.
		if code == dns.RcodeNameError && err == nil {
			return code, nil
		}
		return plugin.NextOrFailure(h.name(), next, ctx, w, req)
	})
}

// addrsFor merges the addrs of every binding answering for fqdn, shuffled for
// load-balancing, along with the answer TTL (the first binding's non-zero TTL
// or the default).
func addrsFor(bindings []Binding, fqdn string) ([]netip.Addr, uint32) {
	var addrs []netip.Addr
	ttl := uint32(defaultTTL)
	for _, b := range bindings {
		if b.FQDN != fqdn {
			continue
		}
		addrs = append(addrs, b.Addrs...)
		if b.TTL != 0 {
			ttl = b.TTL
		}
	}
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})
	return addrs, ttl
}

// delegatesFor returns the merged addrs of the DELEGATING bindings answering
// for fqdn — the upstreams a sub-name query forwards to.
func delegatesFor(bindings []Binding, fqdn string) []netip.Addr {
	var addrs []netip.Addr
	for _, b := range bindings {
		if b.FQDN == fqdn && b.Delegate {
			addrs = append(addrs, b.Addrs...)
		}
	}
	return addrs
}

// zoneFor returns the authoritative zone containing fqdn, or "".
func zoneFor(zones []string, fqdn string) string {
	for _, z := range zones {
		if fqdn == z || strings.HasSuffix(fqdn, "."+z) {
			return z
		}
	}
	return ""
}

func (h *Handler) serveDNS(ctx context.Context, next plugin.Handler, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	if len(req.Question) == 0 {
		return dns.RcodeSuccess, nil
	}

	qname := req.Question[0].Name

	// Strip trailing dot to get the FQDN as stored in the binding set.
	fqdn := strings.TrimSuffix(qname, ".")
	if fqdn == "" {
		return plugin.NextOrFailure(h.name(), next, ctx, w, req)
	}

	snap := h.Source()
	qtype := req.Question[0].Qtype

	// Direct binding match — e.g., "my-tunnel.tun.apoxy.net".
	if addrs, ttl := addrsFor(snap.Bindings, fqdn); len(addrs) > 0 {
		if matched := matchFamily(addrs, qtype); len(matched) > 0 {
			h.observeQuery("hit")
			return writeAddrs(w, req, qname, matched, ttl)
		}
		// The name is ours but has no record of the queried family (e.g. an A
		// query for a v6-only endpoint under musl's parallel A+AAAA). Answer
		// authoritative NODATA — NEVER fall through to the public upstream. A
		// fall-through would both disclose the in-zone name externally and let
		// the upstream's NXDOMAIN (which is per-name, not per-type) poison the
		// sibling-family answer the worker is resolving in parallel.
		h.observeQuery("nodata")
		return writeNoData(w, req, authorityZone(snap.Zones, fqdn))
	}

	// Try recursive resolution by stripping leftmost labels until we find a
	// delegating binding. For example, "my-service.my-tunnel.tun.apoxy.net"
	// strips the "my-service" prefix and matches "my-tunnel.tun.apoxy.net",
	// then forwards "my-service" to the resolvers at those endpoints.
	parts := strings.SplitN(fqdn, ".", 2)
	for len(parts) == 2 && parts[1] != "" {
		subName := parts[0]
		candidate := parts[1]

		if upstreams := delegatesFor(snap.Bindings, candidate); len(upstreams) > 0 {
			h.observeQuery("recursive")
			slog.Debug("Requesting recursive VPC name resolution",
				slog.String("qname", qname),
				slog.String("subName", subName),
				slog.String("hostname", candidate),
				slog.Any("upstreams", upstreams))
			// A delegated sub-name is in an authoritative zone: recursiveResolve
			// writes an authoritative answer/NODATA/NXDOMAIN for it and never
			// falls through, so an unresolved delegated name can't leak to the
			// public upstream either.
			return h.recursiveResolve(ctx, w, req, subName, upstreams, authorityZone(snap.Zones, fqdn))
		}

		// Continue stripping: "a.b.c.tun.apoxy.net" -> try "b.c.tun.apoxy.net".
		rest := strings.SplitN(candidate, ".", 2)
		if len(rest) < 2 {
			break
		}
		parts[0] = parts[0] + "." + rest[0]
		parts[1] = rest[1]
	}

	// If the queried name is within an authoritative zone, return an
	// authoritative NXDOMAIN with a zero-TTL SOA so a caching plugin won't
	// hold a negative entry.
	if zone := zoneFor(snap.Zones, fqdn); zone != "" {
		h.observeQuery("nxdomain")
		return writeNXDomain(w, req, zone)
	}

	// No match — pass to next plugin.
	h.observeQuery("passthrough")
	return plugin.NextOrFailure(h.name(), next, ctx, w, req)
}

// matchFamily returns the subset of addrs matching the queried record type
// (A→IPv4, AAAA→IPv6); other qtypes match nothing.
func matchFamily(addrs []netip.Addr, qtype uint16) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if (a.Is4() && qtype == dns.TypeA) || (a.Is6() && qtype == dns.TypeAAAA) {
			out = append(out, a)
		}
	}
	return out
}

// authorityZone returns the authoritative zone containing fqdn, falling back to
// fqdn itself when no declared zone matches — so an authoritative NODATA/
// NXDOMAIN for a bound name always carries a plausible SOA owner.
func authorityZone(zones []string, fqdn string) string {
	if z := zoneFor(zones, fqdn); z != "" {
		return z
	}
	return fqdn
}

// writeAddrs writes A/AAAA DNS response records for the given addresses.
func writeAddrs(w dns.ResponseWriter, req *dns.Msg, qname string, addrs []netip.Addr, ttl uint32) (int, error) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	for _, ip := range addrs {
		var rr dns.RR
		if ip.Is4() && req.Question[0].Qtype == dns.TypeA {
			rr = &dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				A: ip.AsSlice(),
			}
		} else if ip.Is6() && req.Question[0].Qtype == dns.TypeAAAA {
			rr = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				AAAA: ip.AsSlice(),
			}
		} else {
			continue
		}
		msg.Answer = append(msg.Answer, rr)
	}

	if len(msg.Answer) == 0 {
		return dns.RcodeServerFailure, nil
	}

	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, err
	}

	return dns.RcodeSuccess, nil
}

// soaFor builds the zero-MINIMUM SOA that authoritative negative answers carry
// so a caching plugin won't hold the negative result.
func soaFor(zone string) dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone + ".",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Ns:      "ns1." + zone + ".",
		Mbox:    "hostmaster." + zone + ".",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  0,
	}
}

// writeNXDomain writes an authoritative NXDOMAIN (the name does not exist)
// with a zero-MINIMUM SOA.
func writeNXDomain(w dns.ResponseWriter, req *dns.Msg, zone string) (int, error) {
	msg := new(dns.Msg)
	msg.SetRcode(req, dns.RcodeNameError)
	msg.Authoritative = true
	msg.Ns = []dns.RR{soaFor(zone)}
	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeNameError, nil
}

// writeNoData writes an authoritative NODATA response: NOERROR with no answers
// and a zero-MINIMUM SOA. It says "this name exists but has no record of the
// queried type" — the correct answer for an in-zone name queried for a family
// it doesn't have, so the resolver stub keeps the name and doesn't retry
// against (or leak it to) the public upstream.
func writeNoData(w dns.ResponseWriter, req *dns.Msg, zone string) (int, error) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.Ns = []dns.RR{soaFor(zone)}
	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

// upstreamHostFromAddr builds the delegate resolver address by embedding the
// loopback resolver host:port into the IPv6 overlay address.
func upstreamHostFromAddr(addr netip.Addr) (string, error) {
	if !addr.Is6() {
		return "", fmt.Errorf("expecting v6 address, got %s", addr.String())
	}

	v6, v4 := addr.As16(), delegateResolverV4.As4()
	copy(v6[12:], v4[:])

	return netip.AddrPortFrom(netip.AddrFrom16(v6), delegateResolverPort).String(), nil
}

// aToAAAA converts A records to AAAA records by embedding IPv4 into the IPv6
// /96 prefix.
func aToAAAA(v6base netip.Addr, resp *dns.Msg) {
	v6baseAs16 := v6base.As16()
	for i, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			aaaa := new(dns.AAAA)
			aaaa.Hdr = dns.RR_Header{
				Name:   a.Hdr.Name,
				Rrtype: dns.TypeAAAA,
				Class:  a.Hdr.Class,
				Ttl:    a.Hdr.Ttl,
			}

			aaaa.AAAA = make(net.IP, net.IPv6len)
			copy(aaaa.AAAA[:12], v6baseAs16[:12])
			copy(aaaa.AAAA[12:], a.A)

			resp.Answer[i] = aaaa
		}
	}
}

type upstreamResult struct {
	resp *dns.Msg
	err  error
}

// defaultQueryUpstream queries a single delegate upstream using UDP with TCP
// fallback.
func defaultQueryUpstream(ctx context.Context, upstream netip.Addr, req *dns.Msg) (*dns.Msg, error) {
	addr, err := upstreamHostFromAddr(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream address %s: %w", upstream, err)
	}

	udpClient := &dns.Client{
		Net:     "udp",
		Dialer:  &net.Dialer{Timeout: upstreamTimeout},
		Timeout: upstreamTimeout,
	}
	resp, _, err := udpClient.ExchangeContext(ctx, req, addr)
	if err != nil {
		slog.Error("UDP delegate query failed, retrying with TCP",
			slog.String("addr", addr),
			slog.Any("error", err))
		tcpClient := &dns.Client{
			Net:     "tcp",
			Dialer:  &net.Dialer{Timeout: upstreamTimeout},
			Timeout: upstreamTimeout,
		}
		resp, _, err = tcpClient.ExchangeContext(ctx, req, addr)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (h *Handler) doQueryUpstream(ctx context.Context, upstream netip.Addr, req *dns.Msg) (*dns.Msg, error) {
	if h.QueryUpstream != nil {
		return h.QueryUpstream(ctx, upstream, req)
	}
	return defaultQueryUpstream(ctx, upstream, req)
}

func (h *Handler) recursiveResolve(
	ctx context.Context,
	w dns.ResponseWriter,
	req *dns.Msg,
	name string,
	upstreams []netip.Addr,
	zone string,
) (int, error) {
	resolveStart := time.Now()
	defer func() {
		if h.Metrics.RecursiveDuration != nil {
			h.Metrics.RecursiveDuration(time.Since(resolveStart).Seconds())
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	rReq := req.Copy()
	rReq.Question[0].Name = name + "."
	rReq.RecursionDesired = true

	// Only AAAA is resolved recursively (the delegate answers over the overlay,
	// v6-only). Any other type on a delegated in-zone name is authoritative
	// NODATA, not a fall-through to the public upstream.
	if req.Question[0].Qtype != dns.TypeAAAA {
		return writeNoData(w, req, zone)
	}

	// Rewrite as A for the delegate resolver.
	rReq.Question[0].Qtype = dns.TypeA

	results := make(chan upstreamResult, len(upstreams))
	launched := len(upstreams)
	for _, upstream := range upstreams {
		go func(upstream netip.Addr) {
			resp, err := h.doQueryUpstream(ctx, upstream, rReq)
			if err != nil {
				results <- upstreamResult{err: err}
				return
			}
			aToAAAA(upstream, resp)
			results <- upstreamResult{resp: resp}
		}(upstream)
	}

	// Collect answers. Once the first success arrives, start a grace timer.
	// When it fires, return what we have — abandoning slow/dead upstreams.
	var (
		out      *dns.Msg
		ans      []dns.RR
		received int
	)
	graceTimer := time.NewTimer(0)
	graceTimer.Stop()
	defer graceTimer.Stop()

collect:
	for received < launched {
		select {
		case res := <-results:
			received++
			if res.err != nil {
				continue
			}
			if out == nil {
				out = &dns.Msg{}
				res.resp.CopyTo(out)
				out.Question = req.Question
				graceTimer.Reset(gracePeriod)
			}
			ans = append(ans, res.resp.Answer...)
		case <-graceTimer.C:
			abandoned := launched - received
			if abandoned > 0 {
				slog.Info("Grace period expired, abandoning slow delegate upstreams",
					slog.Int("abandoned", abandoned),
					slog.Int("answered", received))
				if h.Metrics.UpstreamAbandoned != nil {
					h.Metrics.UpstreamAbandoned(abandoned)
				}
			}
			break collect
		case <-ctx.Done():
			break collect
		}
	}
	cancel()

	if len(ans) == 0 {
		// No delegate had an answer: authoritative NXDOMAIN for the in-zone
		// name, not a fall-through that would leak it to the public upstream.
		return writeNXDomain(w, req, zone)
	}

	// Clamp and shuffle answers for load-balancing.
	if maxAnswers > 0 && len(ans) > maxAnswers {
		ans = ans[:maxAnswers]
	}
	rand.Shuffle(len(ans), func(i, j int) {
		ans[i], ans[j] = ans[j], ans[i]
	})
	// Rewrite each answer's owner name to the original qname. The delegate was
	// queried for the bare sub-label ("svc."), so its records carry that name;
	// a validating stub requires the answer name to match the question, and
	// discards the whole RRset otherwise.
	for _, rr := range ans {
		rr.Header().Name = req.Question[0].Name
	}
	out.Answer = ans

	if err := w.WriteMsg(out); err != nil {
		return dns.RcodeServerFailure, err
	}

	return dns.RcodeSuccess, nil
}
