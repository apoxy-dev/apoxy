// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package egressfwd

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	sentrystack "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
)

func TestRoutedUDPDialer_DNSRewritesToResolver(t *testing.T) {
	const resolver = "127.0.0.1:5353"
	d := newRoutedUDPDialer(&sentrystack.InitStr{DNSResolvers: []string{resolver}})

	// The guest sends DNS to the sandbox gateway IP (192.0.2.1:53); the dialer
	// must ignore that and connect to the configured resolver. UDP "dial" does no
	// handshake, so this succeeds regardless of whether anything listens.
	conn, err := d.DialUDP(context.Background(),
		netip.MustParseAddrPort("10.0.0.2:5300"),
		netip.MustParseAddrPort("192.0.2.1:53"))
	if err != nil {
		t.Fatalf("DialUDP(:53): %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != resolver {
		t.Fatalf("dialed %s, want resolver %s", got, resolver)
	}
}

func TestRoutedUDPDialer_Denies(t *testing.T) {
	cases := []struct {
		name      string
		resolvers []string
		dst       string
	}{
		{name: "non-DNS UDP", resolvers: []string{"1.1.1.1:53"}, dst: "203.0.113.5:443"},
		{name: "non-DNS UDP high port", resolvers: []string{"1.1.1.1:53"}, dst: "203.0.113.5:8443"},
		{name: "DNS with no resolver configured", resolvers: nil, dst: "192.0.2.1:53"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newRoutedUDPDialer(&sentrystack.InitStr{DNSResolvers: tc.resolvers})
			_, err := d.DialUDP(context.Background(),
				netip.MustParseAddrPort("10.0.0.2:5300"),
				netip.MustParseAddrPort(tc.dst))
			if !errors.Is(err, ErrNonDNSUDPDenied) {
				t.Fatalf("DialUDP err = %v, want ErrNonDNSUDPDenied", err)
			}
		})
	}
}

func TestNewRoutedUDPDialer_SkipsMalformedResolvers(t *testing.T) {
	d := newRoutedUDPDialer(&sentrystack.InitStr{
		DNSResolvers: []string{"bogus", "1.1.1.1:53", "no-port", "8.8.8.8:53"},
	})
	want := []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("8.8.8.8:53"),
	}
	if len(d.resolvers) != len(want) {
		t.Fatalf("resolvers = %v, want %v", d.resolvers, want)
	}
	for i := range want {
		if d.resolvers[i] != want[i] {
			t.Fatalf("resolver[%d] = %v, want %v", i, d.resolvers[i], want[i])
		}
	}
}
