// SPDX-License-Identifier: AGPL-3.0-only

package vpcdns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p.Masked()
}

// nextRecorder is a terminal next-plugin that records whether the query fell
// through the handler.
type nextRecorder struct {
	called bool
}

func (n *nextRecorder) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	n.called = true
	m := new(dns.Msg)
	m.SetReply(r)
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func (n *nextRecorder) Name() string { return "next-recorder" }

func TestHandlerServeDNS(t *testing.T) {
	tunnelAddr := mustAddr(t, "fd61:706f:7879:100:0:1::")
	snap := Snapshot{
		Zones: []string{"tun.apoxy.net"},
		Bindings: []Binding{
			{
				FQDN:      "my-tunnel.tun.apoxy.net",
				Addrs:     []netip.Addr{tunnelAddr},
				Delegate:  true,
				Reachable: []netip.Prefix{mustPrefix(t, "fd61:706f:7879:100:0:1::/96")},
			},
			{
				FQDN:  "svc.example.internal",
				Addrs: []netip.Addr{mustAddr(t, "10.1.2.3")},
				TTL:   120,
			},
		},
	}

	cases := []struct {
		name        string
		qname       string
		qtype       uint16
		wantRcode   int
		wantAnswers int
		wantAnswer  string // exact first-answer address, "" to skip
		wantTTL     uint32
		wantNext    bool
	}{
		{
			name:        "direct AAAA hit",
			qname:       "my-tunnel.tun.apoxy.net.",
			qtype:       dns.TypeAAAA,
			wantRcode:   dns.RcodeSuccess,
			wantAnswers: 1,
			wantAnswer:  "fd61:706f:7879:100:0:1::",
			wantTTL:     defaultTTL,
		},
		{
			name:        "direct A hit with binding TTL",
			qname:       "svc.example.internal.",
			qtype:       dns.TypeA,
			wantRcode:   dns.RcodeSuccess,
			wantAnswers: 1,
			wantAnswer:  "10.1.2.3",
			wantTTL:     120,
		},
		{
			// A BOUND but out-of-zone name (an internal service, no declared
			// zone) with a family mismatch is still "ours": it returns an
			// authoritative NODATA (SOA owner falls back to the fqdn itself),
			// NOT a fall-through. Falling through would disclose the bound name
			// to the public upstream.
			name:        "out-of-zone bound name family mismatch returns NODATA",
			qname:       "svc.example.internal.",
			qtype:       dns.TypeAAAA,
			wantRcode:   dns.RcodeSuccess,
			wantAnswers: 0,
			wantNext:    false,
		},
		{
			// Core of the in-zone-leak fix: an IN-ZONE name that exists but has
			// no record of the queried family must return an authoritative
			// NODATA (success, zero answers), NOT fall through to upstream.
			// Falling through would leak the in-zone name to the public
			// resolver and could resolve it to an attacker-controlled address.
			name:        "in-zone family mismatch returns authoritative NODATA",
			qname:       "my-tunnel.tun.apoxy.net.",
			qtype:       dns.TypeA,
			wantRcode:   dns.RcodeSuccess,
			wantAnswers: 0,
			wantNext:    false,
		},
		{
			name:      "unbound in-zone name gets authoritative NXDOMAIN",
			qname:     "nope.tun.apoxy.net.",
			qtype:     dns.TypeAAAA,
			wantRcode: dns.RcodeNameError,
		},
		{
			name:      "zone apex miss gets authoritative NXDOMAIN",
			qname:     "tun.apoxy.net.",
			qtype:     dns.TypeAAAA,
			wantRcode: dns.RcodeNameError,
		},
		{
			name:      "out-of-zone name passes through to next",
			qname:     "example.com.",
			qtype:     dns.TypeA,
			wantRcode: dns.RcodeSuccess,
			wantNext:  true,
		},
		{
			name:      "sub-name of a non-delegating binding passes through",
			qname:     "sub.svc.example.internal.",
			qtype:     dns.TypeAAAA,
			wantRcode: dns.RcodeSuccess,
			wantNext:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{Source: func() Snapshot { return snap }}
			next := &nextRecorder{}
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			req := new(dns.Msg)
			req.SetQuestion(tc.qname, tc.qtype)
			code, err := h.Plugin(next).ServeDNS(context.Background(), rec, req)
			if err != nil {
				t.Fatalf("ServeDNS: %v", err)
			}
			if code != tc.wantRcode {
				t.Errorf("rcode = %d; want %d", code, tc.wantRcode)
			}
			if next.called != tc.wantNext {
				t.Errorf("next called = %v; want %v", next.called, tc.wantNext)
			}
			if tc.wantNext || tc.wantRcode != dns.RcodeSuccess {
				return
			}
			if rec.Msg == nil {
				t.Fatal("no response written")
			}
			if !rec.Msg.Authoritative {
				t.Error("answer not authoritative")
			}
			if len(rec.Msg.Answer) != tc.wantAnswers {
				t.Fatalf("answers = %d; want %d", len(rec.Msg.Answer), tc.wantAnswers)
			}
			if tc.wantAnswer != "" {
				var got string
				switch rr := rec.Msg.Answer[0].(type) {
				case *dns.A:
					got = rr.A.String()
				case *dns.AAAA:
					got = rr.AAAA.String()
				default:
					t.Fatalf("unexpected answer type %T", rr)
				}
				if got != tc.wantAnswer {
					t.Errorf("answer = %s; want %s", got, tc.wantAnswer)
				}
				if ttl := rec.Msg.Answer[0].Header().Ttl; ttl != tc.wantTTL {
					t.Errorf("ttl = %d; want %d", ttl, tc.wantTTL)
				}
			}
		})
	}

	t.Run("NXDOMAIN carries a zero-TTL SOA for the zone", func(t *testing.T) {
		h := &Handler{Source: func() Snapshot { return snap }}
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		req := new(dns.Msg)
		req.SetQuestion("missing.tun.apoxy.net.", dns.TypeAAAA)
		if _, err := h.Plugin(&nextRecorder{}).ServeDNS(context.Background(), rec, req); err != nil {
			t.Fatalf("ServeDNS: %v", err)
		}
		if rec.Msg == nil || rec.Msg.Rcode != dns.RcodeNameError {
			t.Fatalf("response = %+v; want NXDOMAIN", rec.Msg)
		}
		if len(rec.Msg.Ns) != 1 {
			t.Fatalf("authority records = %d; want 1 SOA", len(rec.Msg.Ns))
		}
		soa, ok := rec.Msg.Ns[0].(*dns.SOA)
		if !ok {
			t.Fatalf("authority record = %T; want SOA", rec.Msg.Ns[0])
		}
		if soa.Hdr.Name != "tun.apoxy.net." || soa.Minttl != 0 {
			t.Errorf("SOA = %+v; want zone tun.apoxy.net. with zero MINIMUM", soa)
		}
	})
}

func TestHandlerDelegation(t *testing.T) {
	base := mustAddr(t, "fd61:706f:7879:100:0:1::")
	snap := Snapshot{
		Zones: []string{"tun.apoxy.net"},
		Bindings: []Binding{{
			FQDN:     "my-tunnel.tun.apoxy.net",
			Addrs:    []netip.Addr{base},
			Delegate: true,
		}},
	}

	var gotUpstream netip.Addr
	var gotQname string
	h := &Handler{
		Source: func() Snapshot { return snap },
		QueryUpstream: func(_ context.Context, upstream netip.Addr, req *dns.Msg) (*dns.Msg, error) {
			gotUpstream = upstream
			gotQname = req.Question[0].Name
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   []byte{10, 0, 0, 5},
			}}
			return resp, nil
		},
	}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	req := new(dns.Msg)
	req.SetQuestion("svc.my-tunnel.tun.apoxy.net.", dns.TypeAAAA)
	code, err := h.Plugin(&nextRecorder{}).ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("rcode = %d; want success", code)
	}
	if gotUpstream != base {
		t.Errorf("delegate upstream = %s; want %s", gotUpstream, base)
	}
	if gotQname != "svc." {
		t.Errorf("delegated qname = %q; want %q (stripped sub-name)", gotQname, "svc.")
	}
	if len(rec.Msg.Answer) != 1 {
		t.Fatalf("answers = %d; want 1", len(rec.Msg.Answer))
	}
	aaaa, ok := rec.Msg.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("answer = %T; want AAAA (v4 answer embedded into the /96)", rec.Msg.Answer[0])
	}
	if want := "fd61:706f:7879:100:0:1:a00:5"; aaaa.AAAA.String() != want {
		t.Errorf("AAAA = %s; want %s", aaaa.AAAA, want)
	}

	t.Run("non-AAAA delegation returns authoritative NODATA, never falls through", func(t *testing.T) {
		next := &nextRecorder{}
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		req := new(dns.Msg)
		req.SetQuestion("svc.my-tunnel.tun.apoxy.net.", dns.TypeA)
		code, err := h.Plugin(next).ServeDNS(context.Background(), rec, req)
		if err != nil {
			t.Fatalf("ServeDNS: %v", err)
		}
		// A delegated sub-name is in an authoritative zone: an A query (the
		// delegate answers v6-only over the overlay) must be answered as
		// authoritative NODATA, NOT leaked to the public upstream — a
		// fall-through would disclose the in-zone name and let an upstream
		// NXDOMAIN poison the parallel AAAA the worker actually needs.
		if next.called {
			t.Error("A-type delegation must NOT fall through to the next plugin")
		}
		if code != dns.RcodeSuccess {
			t.Errorf("rcode = %d; want success (NODATA)", code)
		}
		if rec.Msg == nil || !rec.Msg.Authoritative {
			t.Fatalf("response = %+v; want an authoritative NODATA", rec.Msg)
		}
		if len(rec.Msg.Answer) != 0 {
			t.Errorf("answers = %d; want 0 (NODATA)", len(rec.Msg.Answer))
		}
		if len(rec.Msg.Ns) != 1 {
			t.Errorf("authority = %d; want 1 SOA for the zone", len(rec.Msg.Ns))
		}
	})
}

func TestSnapshotReachable(t *testing.T) {
	snap := Snapshot{
		Bindings: []Binding{
			{
				FQDN:      "a.tun.apoxy.net",
				Reachable: []netip.Prefix{mustPrefix(t, "fd61:706f:7879:100:0:1::/96")},
			},
			{
				FQDN: "no-carveout.tun.apoxy.net",
			},
		},
	}

	cases := []struct {
		name string
		addr string
		want bool
	}{
		{"inside the granted /96", "fd61:706f:7879:100:0:1::5", true},
		{"sibling /96 in the same /72 denied", "fd61:706f:7879:100:0:2::5", false},
		{"unrelated ULA denied", "fdff::1", false},
		{"v4 private denied", "10.0.0.1", false},
		{"v4-mapped form of a granted v6 admitted via unmap", "::ffff:10.0.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := snap.Reachable(mustAddr(t, tc.addr)); got != tc.want {
				t.Errorf("Reachable(%s) = %v; want %v", tc.addr, got, tc.want)
			}
		})
	}

	t.Run("empty snapshot admits nothing", func(t *testing.T) {
		if (Snapshot{}).Reachable(mustAddr(t, "fd61:706f:7879:100:0:1::5")) {
			t.Error("empty snapshot must admit nothing")
		}
	})
}

var _ plugin.Handler = (*nextRecorder)(nil)
