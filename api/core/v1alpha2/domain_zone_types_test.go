package v1alpha2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/api/core/v1alpha3"
)

func TestDomainZoneNameserverStatusConversion(t *testing.T) {
	cases := []struct {
		name string
		in   *NameserverStatus
	}{
		{name: "no nameserver status"},
		{name: "empty nameserver status", in: &NameserverStatus{}},
		{
			name: "required and current names",
			in: &NameserverStatus{
				Required: []string{"ns1.example.net", "ns2.example.net"},
				Current:  []string{"ns1.example.org"},
			},
		},
		{
			name: "two sets",
			in: &NameserverStatus{
				Required: []string{"ns1-b.example.net", "ns2-b.example.net"},
				Sets:     []string{"a", "b"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &DomainZone{Status: DomainZoneStatus{Nameservers: tc.in}}

			var stored v1alpha3.DomainZone
			require.NoError(t, in.ConvertToStorageVersion(&stored))
			if tc.in == nil {
				require.Nil(t, stored.Status.Nameservers)
			} else {
				require.NotNil(t, stored.Status.Nameservers)
				require.Equal(t, tc.in.Required, stored.Status.Nameservers.Required)
				require.Equal(t, tc.in.Current, stored.Status.Nameservers.Current)
				require.Equal(t, tc.in.Sets, stored.Status.Nameservers.Sets)
			}

			var out DomainZone
			require.NoError(t, out.ConvertFromStorageVersion(&stored))
			require.Equal(t, tc.in, out.Status.Nameservers)
		})
	}
}

func TestDomainZoneClaimStatusConversion(t *testing.T) {
	cases := []struct {
		name string
		in   *ZoneClaimStatus
	}{
		{name: "no claim status"},
		{name: "empty claim status", in: &ZoneClaimStatus{}},
		{
			name: "TXT record, claim not held",
			in: &ZoneClaimStatus{
				TXTName:  "_apoxy-zone-challenge.example.org",
				TXTValue: "apoxy-zone-claim=0123456789abcdef",
			},
		},
		{
			name: "claim held",
			in: &ZoneClaimStatus{
				TXTName:  "_apoxy-zone-challenge.example.org",
				TXTValue: "apoxy-zone-claim=0123456789abcdef",
				Held:     true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &DomainZone{Status: DomainZoneStatus{Claim: tc.in}}

			var stored v1alpha3.DomainZone
			require.NoError(t, in.ConvertToStorageVersion(&stored))
			if tc.in == nil {
				require.Nil(t, stored.Status.Claim)
			} else {
				require.Equal(t, &v1alpha3.ZoneClaimStatus{
					TXTName:  tc.in.TXTName,
					TXTValue: tc.in.TXTValue,
					Held:     tc.in.Held,
				}, stored.Status.Claim)
			}

			var out DomainZone
			require.NoError(t, out.ConvertFromStorageVersion(&stored))
			require.Equal(t, tc.in, out.Status.Claim)
		})
	}
}
