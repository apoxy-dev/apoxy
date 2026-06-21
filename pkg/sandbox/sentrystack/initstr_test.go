// The InitStr envelope is the host<->Sentry wire contract; this test rides
// without a build tag (matching initstr.go) so the round-trip is exercised
// cross-platform, without pulling in the package's linux-only gvisor files.
package sentrystack

import "testing"

// TestInitStrRoundTrip locks the JSON envelope: Encode stamps the version and
// every field survives a Decode unchanged.
func TestInitStrRoundTrip(t *testing.T) {
	in := &InitStr{
		SandboxID:       "sb",
		Eth0V4:          "10.200.0.6",
		Eth0V4PrefixLen: 32,
		Eth0MAC:         "02:aa:bb:cc:dd:ee",
		GatewayV4:       "10.200.0.5",
		IMDSHostAddr:    "127.0.0.1:80",
		EgressHostAddr:  "127.0.0.1:90",
		IMDSV4:          "169.254.169.254:80",
		DNSResolvers:    []string{"1.1.1.1:53", "8.8.8.8:53"},
	}

	enc, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if in.Version != initStrVersion {
		t.Errorf("Encode must stamp Version=%d; got %d", initStrVersion, in.Version)
	}

	out, err := DecodeInitStr(enc)
	if err != nil {
		t.Fatalf("DecodeInitStr: %v", err)
	}
	if out.SandboxID != in.SandboxID ||
		out.Eth0V4 != in.Eth0V4 || out.Eth0V4PrefixLen != in.Eth0V4PrefixLen ||
		out.Eth0MAC != in.Eth0MAC || out.GatewayV4 != in.GatewayV4 ||
		out.IMDSHostAddr != in.IMDSHostAddr || out.EgressHostAddr != in.EgressHostAddr ||
		out.IMDSV4 != in.IMDSV4 {
		t.Errorf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
	if len(out.DNSResolvers) != 2 || out.DNSResolvers[0] != "1.1.1.1:53" || out.DNSResolvers[1] != "8.8.8.8:53" {
		t.Errorf("DNSResolvers round-trip = %v; want [1.1.1.1:53 8.8.8.8:53]", out.DNSResolvers)
	}
}

// An empty payload decodes to a version-stamped, otherwise-zero envelope
// (the lo-only sandbox case).
func TestDecodeInitStr_Empty(t *testing.T) {
	out, err := DecodeInitStr("")
	if err != nil {
		t.Fatalf("DecodeInitStr(\"\"): %v", err)
	}
	if out.Version != initStrVersion {
		t.Errorf("empty decode Version = %d; want %d", out.Version, initStrVersion)
	}
	if out.SandboxID != "" || out.Eth0V4 != "" {
		t.Errorf("empty decode should be zero-valued; got %+v", out)
	}
}

// A version skew must fail loudly rather than silently misread fields.
func TestDecodeInitStr_VersionMismatch(t *testing.T) {
	if _, err := DecodeInitStr(`{"v":99,"sandbox_id":"x"}`); err == nil {
		t.Fatal("expected a version-mismatch error, got nil")
	}
}

// Malformed JSON is an error, not a zero envelope.
func TestDecodeInitStr_BadJSON(t *testing.T) {
	if _, err := DecodeInitStr("{not json"); err == nil {
		t.Fatal("expected a decode error for malformed JSON, got nil")
	}
}
