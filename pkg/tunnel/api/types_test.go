package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectRequestJSON(t *testing.T) {
	cases := []struct {
		name string
		in   ConnectRequest
	}{
		{
			name: "all fields",
			in: ConnectRequest{
				Agent:            "agent-1",
				MetricsPort:      9090,
				Labels:           map[string]string{"app": "payments", "env": "prod"},
				AdvertisedRoutes: []string{"10.0.0.0/8", "fd00::/64"},
				AgentInstance:    "5cbe0a7c-7b0a-4a3e-9c0e-2f6f6f2b7a11",
			},
		},
		{
			name: "legacy fields only",
			in:   ConnectRequest{Agent: "agent-1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := json.Marshal(tc.in)
			require.NoError(t, err)

			var out ConnectRequest
			require.NoError(t, json.Unmarshal(buf, &out))
			require.Equal(t, tc.in, out)
		})
	}

	t.Run("legacy body decodes with new fields empty", func(t *testing.T) {
		var out ConnectRequest
		require.NoError(t, json.Unmarshal([]byte(`{"agent":"agent-1","metricsPort":9090}`), &out))
		require.Equal(t, ConnectRequest{Agent: "agent-1", MetricsPort: 9090}, out)
	})

	t.Run("new fields omitted when empty", func(t *testing.T) {
		buf, err := json.Marshal(ConnectRequest{Agent: "agent-1"})
		require.NoError(t, err)
		require.JSONEq(t, `{"agent":"agent-1"}`, string(buf))
	})
}
