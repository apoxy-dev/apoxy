//go:build linux

package sandbox

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
)

// synthesizeSandboxMAC must be a stable, locally-administered (0x02 prefix) MAC
// derived from sha256(id)[:5], so a restarted sandbox sees the same address.
func TestSynthesizeSandboxMAC(t *testing.T) {
	const id = "sandbox-abc"
	got := synthesizeSandboxMAC(id)

	hw, err := net.ParseMAC(got)
	if err != nil {
		t.Fatalf("synthesizeSandboxMAC(%q) = %q is not a valid MAC: %v", id, got, err)
	}
	if hw[0] != 0x02 {
		t.Errorf("MAC %q is not locally administered (first octet != 0x02)", got)
	}

	sum := sha256.Sum256([]byte(id))
	want := fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", sum[0], sum[1], sum[2], sum[3], sum[4])
	if got != want {
		t.Errorf("synthesizeSandboxMAC(%q) = %q; want %q", id, got, want)
	}

	if again := synthesizeSandboxMAC(id); again != got {
		t.Errorf("MAC not stable across calls: %q vs %q", got, again)
	}
	if other := synthesizeSandboxMAC("different-id"); other == got {
		t.Errorf("distinct IDs produced the same MAC %q", got)
	}
}

// buildSandboxInitStr is the core's per-sandbox init-payload assembly seam: it
// fills the addressing fields it owns (ID, eth0 /32, synthesized MAC, gateway)
// and copies the opaque egress fields through verbatim.
func TestBuildSandboxInitStr(t *testing.T) {
	sb := &Instance{
		ID:        SandboxID("sb-1"),
		SandboxIP: netip.MustParseAddr("10.200.0.6"),
		GatewayIP: netip.MustParseAddr("10.200.0.5"),
	}
	eg := EgressInit{
		IMDSHostAddr:   "127.0.0.1:8080",
		EgressHostAddr: "127.0.0.1:9090",
		IMDSV4:         "169.254.169.254:80",
		DNSResolvers:   []string{"1.1.1.1:53"},
	}

	enc, err := buildSandboxInitStr(sb, eg)
	if err != nil {
		t.Fatalf("buildSandboxInitStr: %v", err)
	}
	is, err := sentrystack.DecodeInitStr(enc)
	if err != nil {
		t.Fatalf("DecodeInitStr: %v", err)
	}

	// Addressing the core owns.
	if is.SandboxID != "sb-1" {
		t.Errorf("SandboxID = %q; want sb-1", is.SandboxID)
	}
	if is.Eth0V4 != "10.200.0.6" || is.Eth0V4PrefixLen != 32 {
		t.Errorf("eth0 = %q/%d; want 10.200.0.6/32", is.Eth0V4, is.Eth0V4PrefixLen)
	}
	if is.GatewayV4 != "10.200.0.5" {
		t.Errorf("GatewayV4 = %q; want 10.200.0.5", is.GatewayV4)
	}
	if is.Eth0MAC != synthesizeSandboxMAC("sb-1") {
		t.Errorf("Eth0MAC = %q; want %q", is.Eth0MAC, synthesizeSandboxMAC("sb-1"))
	}
	// Opaque egress passthrough, verbatim.
	if is.IMDSHostAddr != eg.IMDSHostAddr || is.EgressHostAddr != eg.EgressHostAddr || is.IMDSV4 != eg.IMDSV4 {
		t.Errorf("egress fields not passed through verbatim: %+v", is)
	}
	if len(is.DNSResolvers) != 1 || is.DNSResolvers[0] != "1.1.1.1:53" {
		t.Errorf("DNSResolvers = %v; want [1.1.1.1:53]", is.DNSResolvers)
	}

	// A zero EgressInit yields a lo+eth0 sandbox: addressing present, no egress.
	enc2, err := buildSandboxInitStr(sb, EgressInit{})
	if err != nil {
		t.Fatalf("buildSandboxInitStr (no egress): %v", err)
	}
	is2, err := sentrystack.DecodeInitStr(enc2)
	if err != nil {
		t.Fatalf("DecodeInitStr (no egress): %v", err)
	}
	if is2.EgressHostAddr != "" || is2.IMDSHostAddr != "" || len(is2.DNSResolvers) != 0 {
		t.Errorf("zero EgressInit must produce no egress routing: %+v", is2)
	}
	if is2.Eth0V4 != "10.200.0.6" {
		t.Errorf("addressing must survive a zero EgressInit: eth0=%q", is2.Eth0V4)
	}
}
