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

func TestEgressVerdictRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		allow bool
	}{
		{name: "allow", allow: true},
		{name: "deny", allow: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteEgressVerdict(&buf, tc.allow); err != nil {
				t.Fatalf("WriteEgressVerdict: %v", err)
			}
			// The reader must consume exactly the verdict byte so the caller can
			// splice the remaining stream: write a trailing sentinel and assert
			// it survives untouched.
			buf.WriteString("PAYLOAD")
			got, err := ReadEgressVerdict(&buf)
			if err != nil {
				t.Fatalf("ReadEgressVerdict: %v", err)
			}
			if got != tc.allow {
				t.Fatalf("verdict = %v, want %v", got, tc.allow)
			}
			if rest := buf.String(); rest != "PAYLOAD" {
				t.Fatalf("stream after verdict = %q, want %q", rest, "PAYLOAD")
			}
		})
	}

	t.Run("EOF fails closed", func(t *testing.T) {
		if allow, err := ReadEgressVerdict(bytes.NewReader(nil)); err == nil || allow {
			t.Fatalf("ReadEgressVerdict(empty) = (%v, %v), want (false, error)", allow, err)
		}
	})
	t.Run("unknown byte fails closed", func(t *testing.T) {
		if allow, err := ReadEgressVerdict(bytes.NewReader([]byte{0x7f})); err == nil || allow {
			t.Fatalf("ReadEgressVerdict(0x7f) = (%v, %v), want (false, error)", allow, err)
		}
	})
}

func TestEgressPreambleRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		src     netip.AddrPort
		dst     netip.AddrPort
		dstName string
	}{
		{
			name: "v4 no name",
			src:  netip.MustParseAddrPort("10.200.0.6:40000"),
			dst:  netip.MustParseAddrPort("203.0.113.5:80"),
		},
		{
			name: "v6 no name",
			src:  netip.MustParseAddrPort("[fd00:ec2::ffff]:40001"),
			dst:  netip.MustParseAddrPort("[2606:4700::1]:443"),
		},
		{
			name:    "v4 with hostname",
			src:     netip.MustParseAddrPort("10.200.0.6:40000"),
			dst:     netip.MustParseAddrPort("203.0.113.5:80"),
			dstName: "api.stripe.com",
		},
		{
			name:    "v6 with hostname",
			src:     netip.MustParseAddrPort("[fd00:ec2::ffff]:40001"),
			dst:     netip.MustParseAddrPort("[2606:4700::1]:443"),
			dstName: "cloudflare-dns.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteEgressPreamble(&buf, tc.src, tc.dst, tc.dstName); err != nil {
				t.Fatalf("WriteEgressPreamble: %v", err)
			}
			// The reader must land exactly after the newline so the caller can
			// splice the remaining stream: write a trailing sentinel and assert
			// it survives untouched.
			buf.WriteString("PAYLOAD")

			r := bufio.NewReader(&buf)
			gotSrc, gotDst, gotName, err := ReadEgressPreamble(r)
			if err != nil {
				t.Fatalf("ReadEgressPreamble: %v", err)
			}
			if gotSrc != tc.src {
				t.Errorf("src = %v, want %v", gotSrc, tc.src)
			}
			if gotDst != tc.dst {
				t.Errorf("dst = %v, want %v", gotDst, tc.dst)
			}
			if gotName != tc.dstName {
				t.Errorf("dstName = %q, want %q", gotName, tc.dstName)
			}
			rest, _ := r.ReadString(0)
			if rest != "PAYLOAD" {
				t.Errorf("reader not positioned after preamble: leftover = %q, want %q", rest, "PAYLOAD")
			}
		})
	}
}

// TestWriteEgressPreambleRejectsInvalid guards write-time validation: an invalid
// src/dst must fail loudly rather than emit a token the reader later rejects for
// the wrong reason, and a dstName with whitespace would corrupt the line framing.
func TestWriteEgressPreambleRejectsInvalid(t *testing.T) {
	valid := netip.MustParseAddrPort("10.0.0.1:1")
	cases := []struct {
		name    string
		src, dst netip.AddrPort
		dstName string
	}{
		{name: "invalid dst", src: valid, dst: netip.AddrPort{}},
		{name: "invalid src", src: netip.AddrPort{}, dst: valid},
		{name: "both invalid", src: netip.AddrPort{}, dst: netip.AddrPort{}},
		{name: "dstName with space", src: valid, dst: valid, dstName: "bad host"},
		{name: "dstName with newline", src: valid, dst: valid, dstName: "bad\nhost"},
		{name: "dstName with tab", src: valid, dst: valid, dstName: "bad\thost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteEgressPreamble(&buf, tc.src, tc.dst, tc.dstName); err == nil {
				t.Fatal("WriteEgressPreamble accepted invalid input; want error")
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
		{name: "v1 magic rejected", line: "apoxy-egress/1 10.0.0.1:1 10.0.0.2:2\n"},
		{name: "too few fields", line: "apoxy-egress/2 10.0.0.1:1\n"},
		{name: "too many fields", line: "apoxy-egress/2 10.0.0.1:1 10.0.0.2:2 host extra\n"},
		{name: "bad src", line: "apoxy-egress/2 nope 10.0.0.2:2\n"},
		{name: "bad dst", line: "apoxy-egress/2 10.0.0.1:1 nope\n"},
		{name: "no newline", line: "apoxy-egress/2 10.0.0.1:1 10.0.0.2:2"},
		// An invalid AddrPort stringifies with a space, producing a 4-token line;
		// the reader parses field[1] as src and rejects it rather than mis-parse.
		{name: "invalid-addrport token", line: "apoxy-egress/2 invalid AddrPort 10.0.0.2:2\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewBufferString(tc.line))
			if _, _, _, err := ReadEgressPreamble(r); err == nil {
				t.Fatalf("ReadEgressPreamble(%q) succeeded; want error", tc.line)
			}
		})
	}
}
