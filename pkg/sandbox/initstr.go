//go:build linux

package sandbox

import (
	"crypto/sha256"
	"fmt"
	"net/netip"

	"github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
)

// buildSandboxInitStr renders the per-sandbox sentrystack InitStr the
// host ships to the Sentry's PluginStack via the CLRK_SENTRYSTACK_INITSTR
// env var on the runsc-create subprocess.
//
// The core fills the addressing fields it owns — SandboxID, eth0 IPv4
// (/32, since loopether short-circuits delivery so single-host eth0 is
// what userspace tooling sees), the synthesized MAC, and the cosmetic
// gateway — and copies the opaque egress fields ([Spec.Egress]) through
// verbatim. A zero EgressInit yields a lo+eth0 sandbox with no egress
// routing, which an installed forwarder (or its absence) interprets as
// direct dial.
func buildSandboxInitStr(sb *Instance, eg EgressInit) (string, error) {
	is := &sentrystack.InitStr{
		SandboxID:      string(sb.ID),
		Eth0MAC:        synthesizeSandboxMAC(string(sb.ID)),
		IMDSHostAddr:   eg.IMDSHostAddr,
		IMDSV4:         eg.IMDSV4,
		IMDSV6:         eg.IMDSV6,
		EgressHostAddr: eg.EgressHostAddr,
		DNSResolvers:   eg.DNSResolvers,
	}
	if sb.SandboxIP.IsValid() && sb.SandboxIP.Is4() {
		is.Eth0V4 = sb.SandboxIP.String()
		is.Eth0V4PrefixLen = 32
		// eth0 also gets a guest-scoped IPv6 ULA (fd00:ec2::<v4>, /128) plus —
		// via wireEth0 — a v6 default route. Without them the netstack has no
		// source address or route for IPv6 destinations, so a guest connect to
		// e.g. an Apoxy overlay (VPC) ULA fails before the egress forwarder
		// ever sees the flow. The value is cosmetic beyond being a valid
		// non-overlay ULA: loopether short-circuits delivery and the forwarder
		// intercepts before any neighbor resolution.
		is.Eth0V6 = sandboxV6(sb.SandboxIP).String()
		is.Eth0V6PrefixLen = 128
	}
	if sb.GatewayIP.IsValid() && sb.GatewayIP.Is4() {
		is.GatewayV4 = sb.GatewayIP.String()
		is.GatewayV6 = sandboxV6(sb.GatewayIP).String()
	}
	// Inbound (ingress) path: when the caller asked for a resident listener,
	// tell the Sentry where the server listens and at which fd to find the
	// host listening socket. The fd is constant (inboundExtraFileFD) because
	// runscStart passes exactly one ExtraFile; see its comment. Sealed here at
	// Create — a value arriving after Create would never reach PreInit.
	if sb.inboundListenAddr != "" {
		is.InboundListenAddr = sb.inboundListenAddr
		is.InboundFDIndex = inboundExtraFileFD
	}
	// Control (resident → host manager) path: when the caller asked for a control
	// channel, tell the Sentry the in-sandbox addr the dispatcher dials and the
	// host loopback TCP addr to splice it to. Sealed at Create alongside inbound;
	// needs no fd (the Sentry dials the host listener directly), so there is no
	// FDIndex analogue.
	if sb.controlForwardAddr != "" && sb.controlHostAddr != "" {
		is.ControlForwardAddr = sb.controlForwardAddr
		is.ControlHostAddr = sb.controlHostAddr
	}
	return is.Encode()
}

// sandboxV6 derives the sandbox's guest-scoped IPv6 address from its IPv4:
// fd00:ec2:: with the v4 in the low 32 bits. Stable per sandbox, unique per
// /30 allocation, and outside the Apoxy overlay ULA (fd61:...), so it can
// never satisfy an overlay membership check.
func sandboxV6(v4 netip.Addr) netip.Addr {
	b := [16]byte{0: 0xfd, 1: 0x00, 2: 0x0e, 3: 0xc2}
	copy(b[12:], v4.AsSlice())
	return netip.AddrFrom16(b)
}

// synthesizeSandboxMAC returns a stable locally-administered MAC for a
// sandbox given its ID. 0x02 prefix marks the address as locally
// administered (not vendor-assigned); the remaining 5 bytes are
// sha256(id)[:5]. Stable per-ID so restarts see the same MAC.
func synthesizeSandboxMAC(id string) string {
	sum := sha256.Sum256([]byte(id))
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", sum[0], sum[1], sum[2], sum[3], sum[4])
}
