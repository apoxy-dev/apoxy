// SPDX-License-Identifier: AGPL-3.0-only

// Portable (no build tag): the framing codec has no gvisor/runsc dependency, so
// it compiles and runs on the developer's macOS host as well as in CI.
package egresswire

import (
	"bufio"
	"bytes"
	"net/netip"
	"testing"
)

func TestEgressPreambleRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		src  netip.AddrPort
		dst  netip.AddrPort
	}{
		{
			name: "v4",
			src:  netip.MustParseAddrPort("10.200.0.6:40000"),
			dst:  netip.MustParseAddrPort("203.0.113.5:80"),
		},
		{
			name: "v6",
			src:  netip.MustParseAddrPort("[fd00:ec2::ffff]:40001"),
			dst:  netip.MustParseAddrPort("[2606:4700::1]:443"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteEgressPreamble(&buf, tc.src, tc.dst); err != nil {
				t.Fatalf("WriteEgressPreamble: %v", err)
			}
			// The reader must land exactly after the newline so the caller can
			// splice the remaining stream: write a trailing sentinel and assert
			// it survives untouched.
			buf.WriteString("PAYLOAD")

			r := bufio.NewReader(&buf)
			gotSrc, gotDst, err := ReadEgressPreamble(r)
			if err != nil {
				t.Fatalf("ReadEgressPreamble: %v", err)
			}
			if gotSrc != tc.src {
				t.Errorf("src = %v, want %v", gotSrc, tc.src)
			}
			if gotDst != tc.dst {
				t.Errorf("dst = %v, want %v", gotDst, tc.dst)
			}
			rest, _ := r.ReadString(0)
			if rest != "PAYLOAD" {
				t.Errorf("reader not positioned after preamble: leftover = %q, want %q", rest, "PAYLOAD")
			}
		})
	}
}

// TestWriteEgressPreambleRejectsInvalidAddr guards both directions: an invalid
// src or dst must fail loudly at write time rather than emit a "invalid AddrPort"
// token that the reader later rejects as malformed for the wrong reason.
func TestWriteEgressPreambleRejectsInvalidAddr(t *testing.T) {
	valid := netip.MustParseAddrPort("10.0.0.1:1")
	cases := []struct {
		name     string
		src, dst netip.AddrPort
	}{
		{name: "invalid dst", src: valid, dst: netip.AddrPort{}},
		{name: "invalid src", src: netip.AddrPort{}, dst: valid},
		{name: "both invalid", src: netip.AddrPort{}, dst: netip.AddrPort{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteEgressPreamble(&buf, tc.src, tc.dst); err == nil {
				t.Fatal("WriteEgressPreamble accepted an invalid address; want error")
			}
			if buf.Len() != 0 {
				t.Fatalf("WriteEgressPreamble wrote %q before failing; want nothing", buf.String())
			}
		})
	}
}

func TestReadEgressPreambleRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{name: "wrong magic", line: "not-apoxy 10.0.0.1:1 10.0.0.2:2\n"},
		{name: "too few fields", line: "apoxy-egress/1 10.0.0.1:1\n"},
		{name: "bad src", line: "apoxy-egress/1 nope 10.0.0.2:2\n"},
		{name: "bad dst", line: "apoxy-egress/1 10.0.0.1:1 nope\n"},
		{name: "no newline", line: "apoxy-egress/1 10.0.0.1:1 10.0.0.2:2"},
		// An invalid AddrPort stringifies with a space, producing a 4-token line
		// the reader must reject rather than mis-parse.
		{name: "invalid-addrport token", line: "apoxy-egress/1 invalid AddrPort 10.0.0.2:2\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewBufferString(tc.line))
			if _, _, err := ReadEgressPreamble(r); err == nil {
				t.Fatalf("ReadEgressPreamble(%q) succeeded; want error", tc.line)
			}
		})
	}
}
