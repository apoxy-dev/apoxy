//go:build linux

package sentrystack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

// TestParseInboundTarget covers the in-sandbox listen-address parsing that
// feeds the inbound forwarder's in-stack dial: loopback routes via lo,
// everything else via eth0, and v4/v6 pick the matching protocol number.
func TestParseInboundTarget(t *testing.T) {
	cases := []struct {
		name      string
		addr      string
		wantNIC   tcpip.NICID
		wantPort  uint16
		wantProto tcpip.NetworkProtocolNumber
		wantErr   bool
	}{
		{name: "loopback_v4", addr: "127.0.0.1:8080", wantNIC: loNICID, wantPort: 8080, wantProto: ipv4.ProtocolNumber},
		{name: "eth0_v4", addr: "10.200.0.6:9090", wantNIC: eth0NICID, wantPort: 9090, wantProto: ipv4.ProtocolNumber},
		{name: "loopback_v6", addr: "[::1]:8080", wantNIC: loNICID, wantPort: 8080, wantProto: ipv6.ProtocolNumber},
		{name: "eth0_v6", addr: "[fd00:ec2::ffff]:443", wantNIC: eth0NICID, wantPort: 443, wantProto: ipv6.ProtocolNumber},
		{name: "garbage", addr: "not-an-addr", wantErr: true},
		{name: "missing_port", addr: "127.0.0.1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			full, proto, err := parseInboundTarget(tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseInboundTarget(%q) = nil error, want error", tc.addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInboundTarget(%q): %v", tc.addr, err)
			}
			if full.NIC != tc.wantNIC {
				t.Errorf("NIC = %d, want %d", full.NIC, tc.wantNIC)
			}
			if full.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", full.Port, tc.wantPort)
			}
			if proto != tc.wantProto {
				t.Errorf("proto = %d, want %d", proto, tc.wantProto)
			}
		})
	}
}
