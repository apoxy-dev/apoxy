package alpha

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveTunnelDefaults(t *testing.T) {
	t.Run("generates a Docker-style name and uses the default VPC", func(t *testing.T) {
		name, network, generated := resolveTunnelDefaults("", "")
		require.True(t, generated)
		require.Regexp(t, regexp.MustCompile(`^[a-z0-9]+-[a-z0-9]+$`), name)
		require.Equal(t, "default", network)
	})

	t.Run("preserves explicit values", func(t *testing.T) {
		name, network, generated := resolveTunnelDefaults("edge-agent", "corp")
		require.False(t, generated)
		require.Equal(t, "edge-agent", name)
		require.Equal(t, "corp", network)
	})
}

func TestTunnelRunDefaultFlags(t *testing.T) {
	require.NotNil(t, tunnelRunCmd.Flags().Lookup("name"))
	require.Equal(t, "default", tunnelRunCmd.Flags().Lookup("vpc").DefValue)
	require.NotEmpty(t, tunnelRunCmd.Flags().Lookup("agent").Deprecated)
	require.NotNil(t, tunnelRunCmd.Flags().Lookup("no-tui"))
}

// TestTunnelRunValidation drives RunE directly with the package flag globals set
// so the up-front validation (which returns before any network I/O) is covered
// without cobra reparsing or contaminating other tests. Globals are restored.
func TestTunnelRunValidation(t *testing.T) {
	origMin, origRoutes, origSeed, origTok := minConns, advertisedRoutes, seedRelayAddr, token
	t.Cleanup(func() {
		minConns, advertisedRoutes, seedRelayAddr, token = origMin, origRoutes, origSeed, origTok
	})

	t.Run("rejects --min-conns below 1", func(t *testing.T) {
		// Seed relay+token set so a passing validation would never reach discovery.
		minConns, advertisedRoutes = 0, nil
		seedRelayAddr, token = "127.0.0.1:6081", "tok"
		err := tunnelRunCmd.RunE(tunnelRunCmd, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "min-conns")
	})

	t.Run("rejects an invalid --route CIDR up front", func(t *testing.T) {
		minConns, advertisedRoutes = 1, []string{"10.0.0.0/24", "not-a-cidr"}
		seedRelayAddr, token = "127.0.0.1:6081", "tok"
		err := tunnelRunCmd.RunE(tunnelRunCmd, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid --route")
		require.Contains(t, err.Error(), "not-a-cidr")
	})
}
