// SPDX-License-Identifier: AGPL-3.0-only

package vpctest

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

func newCAs(t *testing.T) (*CA, *CA) {
	t.Helper()
	ca, err := NewCA()
	require.NoError(t, err)
	other, err := NewCA()
	require.NoError(t, err)
	return ca, other
}

func TestCredential(t *testing.T) {
	ca, other := newCAs(t)
	cases := []struct {
		name    string
		issuer  *CA
		setCA   *CA // Trust.SetCA after NewTrust(ca), if set.
		life    time.Duration
		wantErr bool
	}{
		{name: "same CA", issuer: ca, life: time.Hour},
		{name: "other CA", issuer: other, life: time.Hour, wantErr: true},
		{name: "new CA after SetCA", issuer: other, setCA: other, life: time.Hour},
		{name: "old CA after SetCA", issuer: ca, setCA: other, life: time.Hour, wantErr: true},
		{name: "ended", issuer: ca, life: -time.Millisecond, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := tc.issuer.Credential("project-a", "vpc-a", "agent-1", tc.life)
			require.NoError(t, err)
			trust := NewTrust(ca)
			if tc.setCA != nil {
				trust.SetCA(tc.setCA)
			}
			roots, err := trust.AgentCA()
			require.NoError(t, err)
			// The relay checks agent certs with identity.Verify.
			id, err := identity.Verify([]*x509.Certificate{cred.Cert}, identity.VerifyOptions{
				Roots: roots, Project: "project-a", VPC: "vpc-a",
			})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, identity.ID{Project: "project-a", VPC: "vpc-a", Agent: "agent-1"}, id)
			assert.Equal(t, id, cred.ID)
		})
	}
}

func TestRelayCert(t *testing.T) {
	ca, other := newCAs(t)
	cases := []struct {
		name    string
		issuer  *CA
		dnsName string
		wantErr bool
	}{
		{name: "same CA", issuer: ca, dnsName: "relay-1"},
		{name: "other CA", issuer: other, dnsName: "relay-1", wantErr: true},
		{name: "other name", issuer: ca, dnsName: "relay-2", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := tc.issuer.RelayCert("relay-1")
			require.NoError(t, err)
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			require.NoError(t, err)
			require.True(t, cert.PrivateKey.(*ecdsa.PrivateKey).PublicKey.Equal(leaf.PublicKey))
			_, err = leaf.Verify(x509.VerifyOptions{
				Roots: ca.Pool(), DNSName: tc.dnsName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAddresses(t *testing.T) {
	type op struct {
		release bool
		subject string
	}
	cases := []struct {
		name    string
		next    int // Last /96 that the pool gave.
		ops     []op
		wantErr bool // The last op is an Assign that fails.
		overlap map[string]int
		live    map[string]int
	}{
		{
			name:    "one at a time",
			ops:     []op{{subject: "a"}, {release: true, subject: "a"}, {subject: "a"}},
			overlap: map[string]int{"a": 1},
			live:    map[string]int{"a": 1},
		},
		{
			name:    "two live",
			ops:     []op{{subject: "a"}, {subject: "a"}, {release: true, subject: "a"}, {subject: "a"}},
			overlap: map[string]int{"a": 2},
			live:    map[string]int{"a": 2},
		},
		{
			name:    "two agents",
			ops:     []op{{subject: "a"}, {subject: "b"}, {subject: "b"}},
			overlap: map[string]int{"a": 1, "b": 2},
			live:    map[string]int{"a": 1, "b": 2},
		},
		{
			name:    "full",
			next:    0xfffe,
			ops:     []op{{subject: "a"}, {subject: "a"}},
			wantErr: true,
			overlap: map[string]int{"a": 1},
			live:    map[string]int{"a": 1},
		},
	}
	vpc := netip.MustParsePrefix("fd61:706f:7879:12:3400::/72")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Addresses{next: tc.next}
			seen := map[netip.Prefix]bool{}
			for i, o := range tc.ops {
				att := &relay.Attachment{Subject: o.subject}
				if o.release {
					a.Release(att)
					continue
				}
				got, err := a.Assign(context.Background(), att, nil)
				if tc.wantErr && i == len(tc.ops)-1 {
					require.Error(t, err)
					continue
				}
				require.NoError(t, err)
				require.Len(t, got, 1)
				p := got[0]
				assert.Equal(t, 96, p.Bits())
				assert.True(t, vpc.Contains(p.Addr()), "%s is not in %s", p, vpc)
				assert.False(t, seen[p], "%s is given two times", p)
				seen[p] = true
			}
			for s, want := range tc.overlap {
				assert.Equal(t, want, a.Overlap(s), s)
			}
			for s, want := range tc.live {
				assert.Equal(t, want, a.LiveOf(s), s)
			}
		})
	}
}
