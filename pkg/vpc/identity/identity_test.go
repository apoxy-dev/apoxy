package identity

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIDURI(t *testing.T) {
	assert.Equal(t,
		"spiffe://5b6a1c1e-7d33-4f0e-9d6b-2a3f4c5d6e7f/vpc/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/agent/laptop",
		testID.String())
	got, err := ParseID(testID.String())
	require.NoError(t, err)
	assert.Equal(t, testID, got)
}

func TestParseID(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    ID
		wantErr bool
	}{
		{name: "valid", in: "spiffe://p1/vpc/v1/agent/a1", want: ID{Project: "p1", VPC: "v1", Agent: "a1"}},
		{name: "wrong scheme", in: "https://p1/vpc/v1/agent/a1", wantErr: true},
		{name: "no agent", in: "spiffe://p1/vpc/v1", wantErr: true},
		{name: "extra segment", in: "spiffe://p1/vpc/v1/agent/a1/x", wantErr: true},
		{name: "wrong keyword", in: "spiffe://p1/ns/v1/sa/a1", wantErr: true},
		{name: "empty VPC", in: "spiffe://p1/vpc//agent/a1", wantErr: true},
		{name: "dot VPC", in: "spiffe://p1/vpc/../agent/a1", wantErr: true},
		{name: "uppercase project", in: "spiffe://P1/vpc/v1/agent/a1", wantErr: true},
		{name: "empty project", in: "spiffe:///vpc/v1/agent/a1", wantErr: true},
		{name: "port", in: "spiffe://p1:443/vpc/v1/agent/a1", wantErr: true},
		{name: "user", in: "spiffe://u@p1/vpc/v1/agent/a1", wantErr: true},
		{name: "query", in: "spiffe://p1/vpc/v1/agent/a1?x=1", wantErr: true},
		{name: "fragment", in: "spiffe://p1/vpc/v1/agent/a1#x", wantErr: true},
		{name: "escaped path", in: "spiffe://p1/vpc/v%2F1/agent/a1", wantErr: true},
		{name: "uppercase agent", in: "spiffe://p1/vpc/v1/agent/Laptop", wantErr: true},
		{name: "agent with dot", in: "spiffe://p1/vpc/v1/agent/a.b", wantErr: true},
		{name: "agent with underscore", in: "spiffe://p1/vpc/v1/agent/a_b", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseID(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIDFromCert(t *testing.T) {
	other, err := url.Parse("spiffe://p2/vpc/v2/agent/a2")
	require.NoError(t, err)
	cases := []struct {
		name    string
		uris    []*url.URL
		wantErr bool
	}{
		{name: "one SAN", uris: []*url.URL{testID.URI()}},
		{name: "no SAN", wantErr: true},
		{name: "two SANs", uris: []*url.URL{testID.URI(), other}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := IDFromCert(&x509.Certificate{URIs: tc.uris})
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testID, got)
		})
	}
}
