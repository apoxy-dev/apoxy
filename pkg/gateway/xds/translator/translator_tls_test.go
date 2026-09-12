package translator

import (
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
)

func TestBuildXdsUpstreamTLSSocketWthCert(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *ir.TLSUpstreamConfig
		wantSNI  string
		wantSANs int
	}{
		{
			name: "ca certificate without sni",
			cfg: &ir.TLSUpstreamConfig{
				CACertificate: &ir.TLSCACertificate{Name: "ca"},
			},
		},
		{
			name: "ca certificate with sni",
			cfg: &ir.TLSUpstreamConfig{
				CACertificate: &ir.TLSCACertificate{Name: "ca"},
				SNI:           "api.example.com",
			},
			wantSNI:  "api.example.com",
			wantSANs: 1,
		},
		{
			name: "system trust store with sni",
			cfg: &ir.TLSUpstreamConfig{
				UseSystemTrustStore: true,
				SNI:                 "api.example.com",
			},
			wantSNI:  "api.example.com",
			wantSANs: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			socket, err := buildXdsUpstreamTLSSocketWthCert(tc.cfg)
			require.NoError(t, err)

			var ctx tlsv3.UpstreamTlsContext
			require.NoError(t, socket.GetTypedConfig().UnmarshalTo(&ctx))
			require.Equal(t, tc.wantSNI, ctx.Sni)

			var sans []*tlsv3.SubjectAltNameMatcher
			switch v := ctx.CommonTlsContext.ValidationContextType.(type) {
			case *tlsv3.CommonTlsContext_CombinedValidationContext:
				require.NotNil(t, v.CombinedValidationContext.DefaultValidationContext)
				sans = v.CombinedValidationContext.DefaultValidationContext.MatchTypedSubjectAltNames
			case *tlsv3.CommonTlsContext_ValidationContext:
				sans = v.ValidationContext.MatchTypedSubjectAltNames
			default:
				t.Fatalf("unexpected validation context %T", v)
			}
			require.Len(t, sans, tc.wantSANs)
		})
	}
}
