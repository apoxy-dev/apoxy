package alpha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	tunnelagent "github.com/apoxy-dev/apoxy/pkg/tunnel/agent"
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
	require.Equal(t, "", tunnelRunCmd.Flags().Lookup("admin-addr").DefValue)
	require.NotEmpty(t, tunnelRunCmd.Flags().Lookup("health-addr").Deprecated)
	require.NotNil(t, tunnelRunCmd.Flags().Lookup("no-tui"))
}

func TestResolveAdminAddr(t *testing.T) {
	cases := []struct {
		name          string
		admin         string
		health        string
		adminChanged  bool
		healthChanged bool
		want          string
		wantErr       string
	}{
		{name: "disabled by default"},
		{name: "uses explicit admin address", admin: " 127.0.0.1:18080 ", adminChanged: true, want: "127.0.0.1:18080"},
		{name: "supports deprecated health address", health: "127.0.0.1:8081", healthChanged: true, want: "127.0.0.1:8081"},
		{
			name:          "rejects both flags",
			admin:         "127.0.0.1:18080",
			health:        "127.0.0.1:8081",
			adminChanged:  true,
			healthChanged: true,
			wantErr:       "cannot be used together",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveAdminAddr(tc.admin, tc.health, tc.adminChanged, tc.healthChanged)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestTunnelAdminHandler(t *testing.T) {
	tracker := tunnelagent.NewConnectionTracker(2)
	handler := newTunnelAdminHandler(tracker)

	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	require.Equal(t, http.StatusOK, request("/livez").Code)
	require.Equal(t, http.StatusServiceUnavailable, request("/readyz").Code)
	require.Equal(t, http.StatusServiceUnavailable, request("/healthz").Code)

	tracker.ConnectionOpened()
	tracker.ConnectionOpened()
	require.Equal(t, http.StatusOK, request("/readyz").Code)

	metrics := request("/metrics")
	require.Equal(t, http.StatusOK, metrics.Code)
	body, err := io.ReadAll(metrics.Result().Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "tunnel_agent_connections_active 2")
	require.Contains(t, string(body), "tunnel_agent_connections_required 2")
	require.Contains(t, string(body), "tunnel_agent_ready 1")
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
