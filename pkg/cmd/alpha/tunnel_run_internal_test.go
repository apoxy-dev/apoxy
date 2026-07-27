package alpha

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
