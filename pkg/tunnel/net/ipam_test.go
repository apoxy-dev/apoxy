package net

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIPAMReleaseUnknownAddress covers the release of addresses that the IPAM
// does not hold. The IPAM keeps its allocations in memory only, so every
// address recorded before a process restart looks unknown to it.
func TestIPAMReleaseUnknownAddress(t *testing.T) {
	ctx := context.Background()

	newULAIPAM := func(t *testing.T) IPAM {
		t.Helper()
		ipam, err := NewULA(ctx, SystemNetworkID).IPAM(ctx, 128)
		require.NoError(t, err)
		return ipam
	}

	cases := []struct {
		name string
		// ipam builds the IPAM under test and returns the prefix to release.
		ipam func(t *testing.T) (IPAM, netip.Prefix)
	}{
		{
			name: "ula address was never allocated",
			ipam: func(t *testing.T) (IPAM, netip.Prefix) {
				return newULAIPAM(t), netip.MustParsePrefix("fd61:706f:7879::e1d/128")
			},
		},
		{
			name: "ula address was never allocated but siblings were",
			ipam: func(t *testing.T) (IPAM, netip.Prefix) {
				ipam := newULAIPAM(t)
				_, err := ipam.Allocate()
				require.NoError(t, err)
				return ipam, netip.MustParsePrefix("fd61:706f:7879::e1d/128")
			},
		},
		{
			name: "ula address is released twice",
			ipam: func(t *testing.T) (IPAM, netip.Prefix) {
				ipam := newULAIPAM(t)
				addr, err := ipam.Allocate()
				require.NoError(t, err)
				require.NoError(t, ipam.Release(addr))
				return ipam, addr
			},
		},
		{
			name: "v4 address was never allocated",
			ipam: func(t *testing.T) (IPAM, netip.Prefix) {
				return NewIPAMv4(ctx), netip.MustParsePrefix("100.64.7.0/32")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ipam, prefix := tc.ipam(t)
			require.NoError(t, ipam.Release(prefix))
		})
	}
}

// TestIPAMReleaseAllocatedAddress checks that a released address returns to the
// pool, so the tolerance of unknown addresses does not skip the real release.
func TestIPAMReleaseAllocatedAddress(t *testing.T) {
	ctx := context.Background()

	ipam, err := NewULA(ctx, SystemNetworkID).IPAM(ctx, 128)
	require.NoError(t, err)

	addr, err := ipam.Allocate()
	require.NoError(t, err)
	require.NoError(t, ipam.Release(addr))

	again, err := ipam.Allocate()
	require.NoError(t, err)
	require.Equal(t, addr, again, "released address must be handed out again")
}
