// SPDX-License-Identifier: AGPL-3.0-only

// Portable (no build tag): pure policy logic, runs on the developer's macOS
// host and in CI.
package sandbox

import (
	"net/netip"
	"testing"
)

func TestPolicyAllow(t *testing.T) {
	// A representative deny-default policy: allow 10.0.0.0/8 on TCP:443, and
	// allow *.example.com (hostname-bound), everything else denied.
	denyDefault := &Policy{
		DefaultDeny: true,
		Rules: []Rule{
			{
				DestinationCIDRs: []string{"10.0.0.0/8"},
				Ports:            []PortRange{{Start: 443, End: 443}},
				Protocol:         "TCP",
			},
			{
				DestinationHostnames: []string{"*.example.com"},
			},
			{
				// A port-range-only rule (any dst) on 8000-8100.
				Ports: []PortRange{{Start: 8000, End: 8100}},
			},
		},
	}

	cases := []struct {
		name    string
		policy  *Policy
		dst     netip.AddrPort
		proto   string
		dstName string
		want    bool
	}{
		{name: "nil policy allows all", policy: nil, dst: netip.MustParseAddrPort("203.0.113.5:80"), proto: "TCP", want: true},
		{name: "empty allow-all (no rules, no deny)", policy: &Policy{}, dst: netip.MustParseAddrPort("203.0.113.5:80"), proto: "TCP", want: true},
		{name: "deny-all empty policy", policy: &Policy{DefaultDeny: true}, dst: netip.MustParseAddrPort("203.0.113.5:80"), proto: "TCP", want: false},

		{name: "cidr+port+proto match", policy: denyDefault, dst: netip.MustParseAddrPort("10.1.2.3:443"), proto: "TCP", want: true},
		{name: "cidr match but wrong port", policy: denyDefault, dst: netip.MustParseAddrPort("10.1.2.3:80"), proto: "TCP", want: false},
		{name: "cidr+port match but wrong proto", policy: denyDefault, dst: netip.MustParseAddrPort("10.1.2.3:443"), proto: "UDP", want: false},
		{name: "proto case-insensitive", policy: denyDefault, dst: netip.MustParseAddrPort("10.1.2.3:443"), proto: "tcp", want: true},
		{name: "outside cidr denied by default", policy: denyDefault, dst: netip.MustParseAddrPort("192.0.2.1:443"), proto: "TCP", want: false},

		{name: "hostname wildcard match", policy: denyDefault, dst: netip.MustParseAddrPort("203.0.113.9:443"), proto: "TCP", dstName: "api.example.com", want: true},
		{name: "hostname rule needs bound name", policy: denyDefault, dst: netip.MustParseAddrPort("203.0.113.9:443"), proto: "TCP", dstName: "", want: false},
		{name: "hostname apex not matched by wildcard", policy: denyDefault, dst: netip.MustParseAddrPort("203.0.113.9:443"), proto: "TCP", dstName: "example.com", want: false},

		{name: "port-range-only rule matches any dst", policy: denyDefault, dst: netip.MustParseAddrPort("198.51.100.7:8050"), proto: "TCP", want: true},
		{name: "port-range-only rule out of range", policy: denyDefault, dst: netip.MustParseAddrPort("198.51.100.7:9000"), proto: "TCP", want: false},

		{name: "v4-mapped-in-v6 dst still matches v4 cidr", policy: denyDefault, dst: netip.MustParseAddrPort("[::ffff:10.1.2.3]:443"), proto: "TCP", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.Allow(tc.dst, tc.proto, tc.dstName); got != tc.want {
				t.Errorf("Allow(%v, %q, %q) = %v, want %v", tc.dst, tc.proto, tc.dstName, got, tc.want)
			}
		})
	}
}

func TestHostnameMatches(t *testing.T) {
	cases := []struct {
		rule, candidate string
		want            bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "other.example.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "api.example.org", false},
		// Case-insensitive: DNS names are case-insensitive (RFC 4343), so a
		// resolver binding a name in any case must still match the rule.
		{"api.example.com", "API.Example.COM", true},
		{"API.EXAMPLE.COM", "api.example.com", true},
		{"*.example.com", "API.Example.com", true},
		{"*.Example.com", "api.example.COM", true},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"~"+tc.candidate, func(t *testing.T) {
			if got := hostnameMatches(tc.rule, tc.candidate); got != tc.want {
				t.Errorf("hostnameMatches(%q, %q) = %v, want %v", tc.rule, tc.candidate, got, tc.want)
			}
		})
	}
}

func TestPickBackend(t *testing.T) {
	catchAll := BackendListener{Name: "catch-all", Addr: "10.0.0.1:9000", Priority: 1}
	catchAllHi := BackendListener{Name: "catch-all-hi", Addr: "10.0.0.2:9000", Priority: 5}
	port443 := BackendListener{Name: "p443", Addr: "10.0.0.3:9443", MatchPort: 443, Priority: 1}
	port443Hi := BackendListener{Name: "p443-hi", Addr: "10.0.0.4:9443", MatchPort: 443, Priority: 9}
	notReady := BackendListener{Name: "not-ready", Addr: "", MatchPort: 443, Priority: 100}

	cases := []struct {
		name     string
		backends []BackendListener
		dstPort  uint16
		wantName string // "" => expect nil (direct dial)
	}{
		{name: "no backends -> direct", backends: nil, dstPort: 443, wantName: ""},
		{name: "single catch-all", backends: []BackendListener{catchAll}, dstPort: 80, wantName: "catch-all"},
		{name: "specific beats catch-all", backends: []BackendListener{catchAll, port443}, dstPort: 443, wantName: "p443"},
		{name: "catch-all when specific port mismatches", backends: []BackendListener{catchAll, port443}, dstPort: 80, wantName: "catch-all"},
		{name: "priority tiebreak among catch-alls", backends: []BackendListener{catchAll, catchAllHi}, dstPort: 80, wantName: "catch-all-hi"},
		{name: "priority tiebreak among specifics", backends: []BackendListener{port443, port443Hi}, dstPort: 443, wantName: "p443-hi"},
		{name: "empty-addr listener skipped -> direct", backends: []BackendListener{notReady}, dstPort: 443, wantName: ""},
		{name: "empty-addr skipped, falls to catch-all", backends: []BackendListener{notReady, catchAll}, dstPort: 443, wantName: "catch-all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PickBackend(tc.backends, tc.dstPort)
			if tc.wantName == "" {
				if got != nil {
					t.Fatalf("PickBackend = %q, want nil (direct)", got.Name)
				}
				return
			}
			if got == nil {
				t.Fatalf("PickBackend = nil, want %q", tc.wantName)
			}
			if got.Name != tc.wantName {
				t.Errorf("PickBackend = %q, want %q", got.Name, tc.wantName)
			}
		})
	}
}
