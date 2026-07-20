// SPDX-License-Identifier: AGPL-3.0-only

// Package egresswire is the pure wire framing shared by the two ends of the
// compute egress data path: the in-Sentry forwarder (pkg/sandbox/sentrystack/
// egressfwd) writes the preamble, and the host egress bridge (pkg/workerd/host)
// reads it. It is a leaf package with NO build tag and NO init() side effect, so
// importing it to encode/decode a preamble never arms the forwarder — that stays
// an explicit opt-in via a blank import of egressfwd. Keeping the codec here (not
// in egressfwd) is what preserves that opt-in contract: the host bridge needs the
// reader, not the installer.
package egresswire

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// preambleMagic tags the first line the Sentry forwarder writes onto the
// host-bridge connection, announcing the sandbox-visible (src, dst) tuple the
// worker tried to reach — and, since v2, the hostname the worker resolved that
// dst from. The host side reads it to recover the real destination the shared
// bridge socket can't learn from its 5-tuple, and to attribute the flow to the
// qname for hostname-based egress policy.
//
// v3 layout: "apoxy-egress/3 <src> <dst> [<dstName>]\n". The trailing dstName is
// optional — omitted when the flow used a literal IP or the Sentry's DNS-answer
// cache had no binding — so a v3 line is 3 or 4 whitespace-separated fields.
// v3 additionally requires the bridge to answer with a one-byte verdict (see
// WriteEgressVerdict) before any upstream bytes; the forwarder holds the guest
// SYN half-open until it reads the verdict, so a denied flow is refused with an
// RST before any netstack endpoint exists. The magic is bumped on every layout
// change rather than made backward-compatible: the forwarder (writer) and the
// host bridge (reader) ship in the same binary and a resident always boots a
// matching pair, so there is no mixed-version wire on a single connection — a
// mismatched pair fails loudly at the preamble parse instead of deadlocking on
// a verdict that will never come.
//
// A later increment replaces this with a PROXY v2 header carrying identity +
// InvocationID TLVs, which the per-EG Envoy MITM attributes on — the wire
// contract the worker egress bridge enriches on the way to the gateway.
const preambleMagic = "apoxy-egress/3"

// Verdict bytes the host bridge writes back onto the connection immediately
// after evaluating the preamble against SSRF + policy, before any upstream
// data. Printable so a stray verdict in a capture is self-describing.
const (
	verdictAllow = byte('A')
	verdictDeny  = byte('D')
)

// WriteEgressPreamble writes the one-line (src, dst[, dstName]) announcement
// onto w. Both addresses are the sandbox-visible tuple verbatim, so a v4 dst
// carries a v4 src and a v6 dst a v6 src. dstName is the hostname the worker
// resolved dst from (from the Sentry DNS-answer cache), or "" when unknown.
//
// Both src and dst are validated: an invalid AddrPort stringifies to
// "invalid AddrPort" (which contains a space), so emitting it would produce a
// preamble line that ReadEgressPreamble rejects as malformed for a reason
// unrelated to the real bug. Failing here surfaces the malformed address at the
// forwarder's dial with a clear error instead. dstName is likewise rejected if
// it contains whitespace, since the line is whitespace-delimited.
func WriteEgressPreamble(w io.Writer, src, dst netip.AddrPort, dstName string) error {
	if !src.IsValid() {
		return fmt.Errorf("egress preamble: invalid src")
	}
	if !dst.IsValid() {
		return fmt.Errorf("egress preamble: invalid dst")
	}
	if strings.ContainsAny(dstName, " \t\r\n") {
		return fmt.Errorf("egress preamble: dstName %q contains whitespace", dstName)
	}
	var err error
	if dstName == "" {
		_, err = fmt.Fprintf(w, "%s %s %s\n", preambleMagic, src.String(), dst.String())
	} else {
		_, err = fmt.Fprintf(w, "%s %s %s %s\n", preambleMagic, src.String(), dst.String(), dstName)
	}
	if err != nil {
		return fmt.Errorf("writing egress preamble: %w", err)
	}
	return nil
}

// ReadEgressPreamble reads and parses the announcement written by
// WriteEgressPreamble. On success r is positioned at the first byte after the
// newline, so the caller can splice the remainder as the raw stream. dstName is
// "" when the forwarder emitted no hostname (literal-IP flow or DNS-cache miss).
func ReadEgressPreamble(r *bufio.Reader) (src, dst netip.AddrPort, dstName string, err error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, "", fmt.Errorf("reading egress preamble: %w", err)
	}
	fields := strings.Fields(line)
	if (len(fields) != 3 && len(fields) != 4) || fields[0] != preambleMagic {
		return netip.AddrPort{}, netip.AddrPort{}, "", fmt.Errorf("malformed egress preamble %q", strings.TrimSpace(line))
	}
	if src, err = netip.ParseAddrPort(fields[1]); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, "", fmt.Errorf("egress preamble src %q: %w", fields[1], err)
	}
	if dst, err = netip.ParseAddrPort(fields[2]); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, "", fmt.Errorf("egress preamble dst %q: %w", fields[2], err)
	}
	if len(fields) == 4 {
		dstName = fields[3]
	}
	return src, dst, dstName, nil
}

// WriteEgressVerdict writes the bridge's one-byte policy verdict for the flow
// announced by the preceding preamble. The forwarder reads it before completing
// the guest's TCP handshake: deny (or any read failure, which fails closed)
// refuses the SYN with an RST without allocating a netstack endpoint.
func WriteEgressVerdict(w io.Writer, allow bool) error {
	v := verdictDeny
	if allow {
		v = verdictAllow
	}
	if _, err := w.Write([]byte{v}); err != nil {
		return fmt.Errorf("writing egress verdict: %w", err)
	}
	return nil
}

// ReadEgressVerdict reads the verdict written by WriteEgressVerdict. On an
// allow verdict r is positioned at the first upstream byte, so the caller can
// splice the remainder as the raw stream. Any error — including a short read
// from a bridge that closed without answering — must be treated as a deny by
// the caller (fail closed).
func ReadEgressVerdict(r io.Reader) (allow bool, err error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return false, fmt.Errorf("reading egress verdict: %w", err)
	}
	switch b[0] {
	case verdictAllow:
		return true, nil
	case verdictDeny:
		return false, nil
	default:
		return false, fmt.Errorf("malformed egress verdict 0x%02x", b[0])
	}
}
