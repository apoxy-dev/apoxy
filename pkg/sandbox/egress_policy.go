// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"net/netip"
	"strings"
)

// Allow reports whether a dial to dst with the given L4 protocol and
// DNS-bound destination name is permitted under this policy. A rule match
// allows the dial; with no match, DefaultDeny decides (false = allow-all).
// A nil receiver allows everything — the implicit built-in "default" gateway
// (no MITM, no enforcement), mirroring clrk's egress.SandboxPolicy.Allow.
//
// proto is the L4 protocol of the flow ("TCP"); dstName is the hostname the
// sandbox's resolver bound for dst.Addr(), empty when nothing was bound
// (direct-IP dial, or DNS forwarding not yet wired), in which case
// hostname-only rules cannot match.
func (p *Policy) Allow(dst netip.AddrPort, proto, dstName string) bool {
	if p == nil {
		return true
	}
	for i := range p.Rules {
		if p.Rules[i].matches(dst, proto, dstName) {
			return true
		}
	}
	return !p.DefaultDeny
}

// matches reports whether dst/proto/dstName satisfies this rule. Dimensions
// are ANDed; within the destination block CIDR and hostname are ORed (either
// suffices). An absent dimension matches anything. Mirrors clrk's
// routeEntry.matches. CIDR strings are parsed here rather than pre-compiled
// because Rule carries the wire form the config plane pushed; the bridge
// caches a compiled merged policy per config generation so this parse is not
// paid per connection.
func (r *Rule) matches(dst netip.AddrPort, proto, dstName string) bool {
	// Protocol filter (case-insensitive: the wire form is "TCP").
	if r.Protocol != "" && !strings.EqualFold(r.Protocol, proto) {
		return false
	}

	// Destination block: CIDR OR hostname must match when either is present.
	if len(r.DestinationCIDRs) > 0 || len(r.DestinationHostnames) > 0 {
		addr := dst.Addr().Unmap()
		dstMatch := false
		for _, cidrStr := range r.DestinationCIDRs {
			prefix, err := netip.ParsePrefix(cidrStr)
			if err != nil {
				continue
			}
			if prefix.Contains(addr) {
				dstMatch = true
				break
			}
		}
		if !dstMatch && dstName != "" {
			for _, h := range r.DestinationHostnames {
				if hostnameMatches(h, dstName) {
					dstMatch = true
					break
				}
			}
		}
		if !dstMatch {
			return false
		}
	}

	// Port filter.
	if len(r.Ports) > 0 {
		port := int32(dst.Port())
		matched := false
		for _, pr := range r.Ports {
			if port >= pr.Start && port <= pr.End {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// hostnameMatches reports whether candidate satisfies rule. The exact form
// ("api.example.com") requires equality; a leading-"*." wildcard matches
// exactly one extra label (RFC 4592 / gwapiv1.Hostname): "*.example.com"
// matches "api.example.com" but not "example.com" or "a.b.example.com".
//
// Matching is case-insensitive: DNS names are case-insensitive (RFC 4343), and
// the resolver may bind a name in any case, so "API.Example.com" must match an
// "api.example.com" rule. (The protocol dimension likewise uses EqualFold.)
func hostnameMatches(rule, candidate string) bool {
	rule = strings.ToLower(rule)
	candidate = strings.ToLower(candidate)
	if strings.HasPrefix(rule, "*.") {
		suffix := rule[1:]
		if !strings.HasSuffix(candidate, suffix) {
			return false
		}
		return strings.Count(candidate, ".") == strings.Count(rule, ".")
	}
	return rule == candidate
}

// PickBackend selects the best-matching EgressGateway listener for the
// destination port. Most-specific wins — a MatchPort-constrained listener is
// preferred over a catch-all — and ties break on Priority (higher wins).
// Returns nil when no listener matches or every match has an empty Addr (its
// data plane isn't ready); the caller reads nil as "direct dial, no gateway".
// Ported from clrk's bridge pickBackend.
func PickBackend(backends []BackendListener, dstPort uint16) *BackendListener {
	var best *BackendListener
	bestSpecific := false
	for i := range backends {
		b := &backends[i]
		if b.Addr == "" {
			continue
		}
		specific := b.MatchPort != 0 && uint16(b.MatchPort) == dstPort
		if b.MatchPort != 0 && !specific {
			continue
		}
		if best == nil {
			best, bestSpecific = b, specific
			continue
		}
		if specific && !bestSpecific {
			best, bestSpecific = b, specific
			continue
		}
		if specific == bestSpecific && b.Priority > best.Priority {
			best = b
		}
	}
	return best
}
