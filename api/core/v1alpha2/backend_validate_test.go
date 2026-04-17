package v1alpha2

import (
	"testing"
)

func TestBackend_Default_NormalizesProtocolCase(t *testing.T) {
	tests := []struct {
		in, want BackendProto
	}{
		{"", ""},
		{"h2", BackendProtoH2},
		{"H2", BackendProtoH2},
		{"H2c", BackendProtoH2C},
		{"TLS", BackendProtoTLS},
		// Unknown values stay lowercased; the xDS translator will fall
		// through to its plaintext default, but at least diagnostic logs
		// show a stable value rather than whatever case the user typed.
		{"HTTP3", "http3"},
	}
	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			b := &Backend{Spec: BackendSpec{Protocol: tt.in, Endpoints: []BackendEndpoint{{FQDN: "example.com"}}}}
			b.Default()
			if b.Spec.Protocol != tt.want {
				t.Fatalf("Default: protocol = %q, want %q", b.Spec.Protocol, tt.want)
			}
		})
	}
}
