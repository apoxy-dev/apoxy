package v1alpha2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation/field"
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

func TestBackend_Validate(t *testing.T) {
	cases := []struct {
		name      string
		spec      BackendSpec
		wantField string
		wantType  field.ErrorType
	}{
		{
			name: "dynamic proxy without endpoints is valid",
			spec: BackendSpec{DynamicProxy: &DynamicProxySpec{}},
		},
		{
			name: "endpoints without dynamic proxy is valid",
			spec: BackendSpec{Endpoints: []BackendEndpoint{{FQDN: "example.com"}}},
		},
		{
			name: "dynamic proxy with one endpoint is valid",
			spec: BackendSpec{
				DynamicProxy: &DynamicProxySpec{},
				Endpoints:    []BackendEndpoint{{FQDN: "example.com"}},
			},
		},
		{
			name:      "neither dynamic proxy nor endpoints",
			spec:      BackendSpec{},
			wantField: "spec.endpoints",
			wantType:  field.ErrorTypeRequired,
		},
		{
			name: "dynamic proxy with two endpoints",
			spec: BackendSpec{
				DynamicProxy: &DynamicProxySpec{},
				Endpoints: []BackendEndpoint{
					{FQDN: "one.example.com"},
					{FQDN: "two.example.com"},
				},
			},
			wantField: "spec.endpoints",
			wantType:  field.ErrorTypeForbidden,
		},
		{
			name:      "endpoint with both ip and fqdn",
			spec:      BackendSpec{Endpoints: []BackendEndpoint{{IP: "10.0.0.1", FQDN: "example.com"}}},
			wantField: "spec.endpoints.[0].ip",
			wantType:  field.ErrorTypeForbidden,
		},
		{
			name:      "endpoint with an invalid ip",
			spec:      BackendSpec{Endpoints: []BackendEndpoint{{IP: "999.0.0.1"}}},
			wantField: "spec.endpoints.[0].ip",
			wantType:  field.ErrorTypeInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{Spec: tc.spec}
			errs := b.Validate(context.Background())
			if tc.wantField == "" {
				require.Empty(t, errs)
				return
			}
			require.Len(t, errs, 1)
			assert.Equal(t, tc.wantField, errs[0].Field)
			assert.Equal(t, tc.wantType, errs[0].Type)
		})
	}
}
