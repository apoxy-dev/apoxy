// SPDX-License-Identifier: AGPL-3.0-only

package egressfwd

import (
	"container/list"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The DNS-answer cache is pure Go and shared between the two Sentry-side
// forwarders: the UDP forwarder (writer) feeds every :53 response into it, and
// the TCP forwarder (reader) consults it on connect to recover the hostname the
// worker resolved a destination IP from. That qname rides the egress preamble as
// dstName so the host bridge can enforce hostname-based egress policy. It has no
// gvisor dependency and NO build tag, so it compiles (and unit-tests) on every
// platform even though the forwarders that use it are linux-only.
//
// Ported from clrk's internal/sentrystack/dns_cache.go.

const (
	dnsCacheCapacity = 4096

	// TTL clamps. A 0-TTL response still binds for the floor so a transient
	// connection lands before the entry vanishes; a pathological large-TTL
	// upstream answer doesn't pin a stale name forever.
	dnsTTLFloor   = 5 * time.Second
	dnsTTLCeiling = 10 * time.Minute
)

// dnsCache is a bounded LRU keyed by resolved destination IP.
type dnsCache struct {
	cap int
	now func() time.Time

	mu   sync.Mutex
	lru  *list.List
	byIP map[netip.Addr]*list.Element
}

type dnsEntry struct {
	ip        netip.Addr
	name      string
	expiresAt time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		cap:  dnsCacheCapacity,
		lru:  list.New(),
		byIP: make(map[netip.Addr]*list.Element),
		now:  time.Now,
	}
}

// Bind associates resolvedIP → name with ttl clamped to
// [dnsTTLFloor, dnsTTLCeiling]. Last write wins on collision.
func (c *dnsCache) Bind(resolvedIP netip.Addr, name string, ttl time.Duration) {
	if !resolvedIP.IsValid() || name == "" {
		return
	}
	if ttl < dnsTTLFloor {
		ttl = dnsTTLFloor
	}
	if ttl > dnsTTLCeiling {
		ttl = dnsTTLCeiling
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	expires := c.now().Add(ttl)
	if el, ok := c.byIP[resolvedIP]; ok {
		ent := el.Value.(*dnsEntry)
		ent.name = name
		ent.expiresAt = expires
		c.lru.MoveToFront(el)
		return
	}

	ent := &dnsEntry{ip: resolvedIP, name: name, expiresAt: expires}
	el := c.lru.PushFront(ent)
	c.byIP[resolvedIP] = el

	if c.lru.Len() > c.cap {
		oldest := c.lru.Back()
		if oldest != nil {
			old := oldest.Value.(*dnsEntry)
			delete(c.byIP, old.ip)
			c.lru.Remove(oldest)
		}
	}
}

// Lookup returns the bound name for resolvedIP, or "" if no live binding
// exists. Expired entries are pruned lazily on access.
func (c *dnsCache) Lookup(resolvedIP netip.Addr) string {
	if !resolvedIP.IsValid() {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.byIP[resolvedIP]
	if !ok {
		return ""
	}
	ent := el.Value.(*dnsEntry)
	if c.now().After(ent.expiresAt) {
		delete(c.byIP, ent.ip)
		c.lru.Remove(el)
		return ""
	}
	c.lru.MoveToFront(el)
	return ent.name
}

// IngestResponse parses a DNS response and binds each A/AAAA answer IP to the
// question name it answers — but ONLY when the answer record is in bailiwick:
// its owner name must be reachable from a question name through the response's
// own CNAME chain. An answer record for an unrelated name is ignored.
//
// This is a security boundary, not just hygiene: the bound name becomes the
// dstName the host bridge matches hostname egress rules against. Binding every
// answer record unconditionally would let a hostile (or merely sloppy)
// authoritative server attach an extra "api.stripe.com A 6.6.6.6" record to an
// unrelated response and thereby grant an allowlisted name's egress rule to an
// arbitrary IP. Only in-bailiwick answers are attributed.
//
// Errors and malformed messages are silently dropped so a busted reply never
// disrupts DNS forwarding.
func (c *dnsCache) IngestResponse(msg []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return
	}

	var qnames []string
	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}
		qnames = append(qnames, strings.TrimSuffix(q.Name.String(), "."))
	}

	type aRR struct {
		name string
		ip   netip.Addr
		ttl  uint32
	}
	var ips []aRR
	var cnames map[string]string

	for {
		hdr, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}
		name := strings.TrimSuffix(hdr.Name.String(), ".")
		switch hdr.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return
			}
			ips = append(ips, aRR{name: name, ip: netip.AddrFrom4(r.A), ttl: hdr.TTL})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return
			}
			ips = append(ips, aRR{name: name, ip: netip.AddrFrom16(r.AAAA), ttl: hdr.TTL})
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				return
			}
			if cnames == nil {
				cnames = make(map[string]string, 4)
			}
			cnames[name] = strings.TrimSuffix(r.CNAME.String(), ".")
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
		}
	}

	// For each answer record, bind its IP to the question name(s) that reach it
	// through the response's CNAME chain — and ONLY those. An answer record
	// whose owner name is not reachable from any question is out of bailiwick
	// and ignored (no unconditional per-record bind). The qname is what the
	// agent intended, so it is the attributed name; if several questions reach
	// the same IP, last-write-wins leaves the last-listed qname.
	for _, a := range ips {
		ttl := time.Duration(a.ttl) * time.Second
		for _, qn := range qnames {
			if chainReaches(cnames, qn, a.name) {
				c.Bind(a.ip, qn, ttl)
			}
		}
	}
}

// chainReaches reports whether target is reachable from start by following the
// response's CNAME map. start == target counts (a direct A/AAAA answer for the
// question). A hop cap defuses pathological cycles.
func chainReaches(cnames map[string]string, start, target string) bool {
	cur := start
	for hops := 0; hops < 10; hops++ {
		if cur == target {
			return true
		}
		next, ok := cnames[cur]
		if !ok {
			return false
		}
		cur = next
	}
	return false
}
