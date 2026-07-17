// SPDX-License-Identifier: AGPL-3.0-only

// Portable (no build tag): the DNS cache has no gvisor dependency, so it
// compiles and runs on the developer's macOS host as well as in CI.
package egressfwd

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func ipN(n int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
}

func TestDNSCache_BindLookup(t *testing.T) {
	c := newDNSCache()
	ip := netip.MustParseAddr("1.2.3.4")
	c.Bind(ip, "api.example.com", time.Minute)
	if got := c.Lookup(ip); got != "api.example.com" {
		t.Fatalf("Lookup = %q, want api.example.com", got)
	}
	// Unknown IP → "".
	if got := c.Lookup(netip.MustParseAddr("5.6.7.8")); got != "" {
		t.Fatalf("Lookup(unknown) = %q, want empty", got)
	}
	// Last write wins on collision.
	c.Bind(ip, "cdn.example.com", time.Minute)
	if got := c.Lookup(ip); got != "cdn.example.com" {
		t.Fatalf("Lookup after rebind = %q, want cdn.example.com", got)
	}
	// Invalid inputs are no-ops.
	c.Bind(netip.Addr{}, "x", time.Minute)
	c.Bind(ip, "", time.Minute) // empty name ignored → prior binding kept
	if got := c.Lookup(ip); got != "cdn.example.com" {
		t.Fatalf("empty-name Bind clobbered entry: %q", got)
	}
	if got := c.Lookup(netip.Addr{}); got != "" {
		t.Fatalf("Lookup(invalid) = %q, want empty", got)
	}
}

func TestDNSCache_TTLExpiry(t *testing.T) {
	c := newDNSCache()
	base := time.Unix(1000, 0)
	c.now = func() time.Time { return base }
	ip := netip.MustParseAddr("1.2.3.4")
	c.Bind(ip, "h", 10*time.Second)

	c.now = func() time.Time { return base.Add(9 * time.Second) }
	if got := c.Lookup(ip); got != "h" {
		t.Fatalf("pre-expiry Lookup = %q, want h", got)
	}
	c.now = func() time.Time { return base.Add(11 * time.Second) }
	if got := c.Lookup(ip); got != "" {
		t.Fatalf("post-expiry Lookup = %q, want empty", got)
	}
}

func TestDNSCache_TTLFloorAndCeiling(t *testing.T) {
	c := newDNSCache()
	base := time.Unix(0, 0)
	c.now = func() time.Time { return base }
	ip := netip.MustParseAddr("1.1.1.1")

	// A 0-TTL answer still binds for the floor (dnsTTLFloor).
	c.Bind(ip, "h", 0)
	c.now = func() time.Time { return base.Add(dnsTTLFloor - time.Second) }
	if got := c.Lookup(ip); got == "" {
		t.Fatal("0-TTL entry expired before the floor")
	}
	c.now = func() time.Time { return base.Add(dnsTTLFloor + time.Second) }
	if got := c.Lookup(ip); got != "" {
		t.Fatalf("0-TTL entry outlived the floor: %q", got)
	}

	// A huge TTL is clamped to the ceiling (dnsTTLCeiling).
	c.now = func() time.Time { return base }
	c.Bind(ip, "h", 24*time.Hour)
	c.now = func() time.Time { return base.Add(dnsTTLCeiling + time.Minute) }
	if got := c.Lookup(ip); got != "" {
		t.Fatalf("huge-TTL entry outlived the ceiling: %q", got)
	}
}

func TestDNSCache_LRUEviction(t *testing.T) {
	c := newDNSCache()
	// The first-bound entry is the least-recently-used. Fill to capacity, then
	// one past — the oldest must be evicted.
	first := ipN(0)
	c.Bind(first, "first", time.Hour)
	for i := 1; i < dnsCacheCapacity; i++ {
		c.Bind(ipN(i), "h", time.Hour)
	}
	if got := c.Lookup(first); got != "first" {
		t.Fatalf("first entry gone before eviction: %q", got)
	}
	// Re-bind first pushes something else to the back; instead add a fresh one
	// past capacity and assert an eviction happened (len stays at cap).
	c.Bind(ipN(dnsCacheCapacity), "last", time.Hour)
	if c.lru.Len() != dnsCacheCapacity {
		t.Fatalf("cache len = %d, want %d (bounded)", c.lru.Len(), dnsCacheCapacity)
	}
}

func aAnswer(name string, ip [4]byte, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name + "."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.AResource{A: ip},
	}
}

func packResponse(t *testing.T, qname string, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(qname + "."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
		Answers: answers,
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack DNS response: %v", err)
	}
	return b
}

func TestDNSCache_IngestResponse_A(t *testing.T) {
	c := newDNSCache()
	c.IngestResponse(packResponse(t, "api.example.com", aAnswer("api.example.com", [4]byte{1, 2, 3, 4}, 60)))
	if got := c.Lookup(netip.AddrFrom4([4]byte{1, 2, 3, 4})); got != "api.example.com" {
		t.Fatalf("Lookup = %q, want api.example.com", got)
	}
}

func TestDNSCache_IngestResponse_CNAMEChainBindsQName(t *testing.T) {
	c := newDNSCache()
	cname := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("www.example.com."),
			Type:  dnsmessage.TypeCNAME,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.net.")},
	}
	a := aAnswer("cdn.example.net", [4]byte{9, 9, 9, 9}, 60)
	c.IngestResponse(packResponse(t, "www.example.com", cname, a))
	// The qname the worker asked for wins over the CNAME target (last-write-wins),
	// so the flow attributes to the worker's stated intent.
	if got := c.Lookup(netip.AddrFrom4([4]byte{9, 9, 9, 9})); got != "www.example.com" {
		t.Fatalf("Lookup = %q, want www.example.com (qname wins over chain)", got)
	}
}

// TestDNSCache_IngestResponse_OutOfChainNotBoundToQName is the bailiwick
// regression: an answer whose name is NOT reachable from the qname via the
// response's CNAME chain must bind only to its own name, never to the qname.
// The old code bound qname to every A/AAAA record, so a response for one host
// that also carried an unrelated (or attacker-injected) A record would let a
// worker's connect to that record's IP be attributed to — and thus authorized
// by a hostname allowlist entry for — the qname it never resolved.
func TestDNSCache_IngestResponse_OutOfChainNotBoundToQName(t *testing.T) {
	c := newDNSCache()
	// qname = www.example.com with a CNAME to cdn.example.net → 9.9.9.9 (in
	// chain), plus a stray A for evil.example.org → 6.6.6.6 (out of chain).
	cname := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("www.example.com."),
			Type:  dnsmessage.TypeCNAME,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.net.")},
	}
	inChain := aAnswer("cdn.example.net", [4]byte{9, 9, 9, 9}, 60)
	stray := aAnswer("evil.example.org", [4]byte{6, 6, 6, 6}, 60)
	c.IngestResponse(packResponse(t, "www.example.com", cname, inChain, stray))

	// The in-chain IP attributes to the qname.
	if got := c.Lookup(netip.AddrFrom4([4]byte{9, 9, 9, 9})); got != "www.example.com" {
		t.Errorf("in-chain Lookup = %q, want www.example.com", got)
	}
	// The stray record is out of bailiwick: not reachable from the question
	// through the CNAME chain, so it binds to nothing at all. A
	// www.example.com allowlist entry therefore cannot authorize a connect to
	// 6.6.6.6, and neither can any other resolved name.
	if got := c.Lookup(netip.AddrFrom4([4]byte{6, 6, 6, 6})); got != "" {
		t.Errorf("out-of-chain Lookup = %q, want empty (stray record ignored)", got)
	}
}

func TestDNSCache_IngestResponse_Malformed(t *testing.T) {
	c := newDNSCache()
	// Must not panic and must bind nothing.
	c.IngestResponse(nil)
	c.IngestResponse([]byte{0xde, 0xad})
	c.IngestResponse([]byte{0x00})
	if c.lru.Len() != 0 {
		t.Fatalf("malformed ingest created %d entries, want 0", c.lru.Len())
	}
}
