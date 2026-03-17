//go:build linux

package router

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerSNATAddrs(t *testing.T) {
	t.Run("Selects first address per family", func(t *testing.T) {
		ipv4, ipv6 := serverSNATAddrs([]netip.Prefix{
			netip.MustParsePrefix("fd61:706f:7879::/128"),
			netip.MustParsePrefix("10.0.0.1/32"),
			netip.MustParsePrefix("fd61:706f:7879::1/128"),
			netip.MustParsePrefix("10.0.0.2/32"),
		})

		require.Equal(t, netip.MustParseAddr("10.0.0.1"), ipv4)
		require.Equal(t, netip.MustParseAddr("fd61:706f:7879::"), ipv6)
	})

	t.Run("Ignores invalid entries", func(t *testing.T) {
		ipv4, ipv6 := serverSNATAddrs([]netip.Prefix{
			netip.Prefix{},
			netip.MustParsePrefix("fd61:706f:7879::42/128"),
		})

		require.False(t, ipv4.IsValid())
		require.Equal(t, netip.MustParseAddr("fd61:706f:7879::42"), ipv6)
	})
}
