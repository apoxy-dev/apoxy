package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve(t *testing.T) {
	heap := uint64(1 << 30)
	conns := uint64(12345)

	cases := []struct {
		name         string
		opts         []BootstrapOption
		wantHost     string
		wantHeap     *uint64
		wantConns    uint64
		wantIdentity *MetricSinkIdentity
	}{
		{
			name:      "defaults",
			wantHost:  envoyGatewayXdsServerHost,
			wantConns: defaultEnvoyMaxActiveDownstreamConnections,
		},
		{
			name: "options override the defaults",
			opts: []BootstrapOption{
				WithXdsServerHost("apiserver"),
				WithOverloadMaxHeapSizeBytes(heap),
				WithOverloadMaxActiveConnections(conns),
			},
			wantHost:  "apiserver",
			wantHeap:  &heap,
			wantConns: conns,
		},
		{
			name: "the metric sink identity is carried",
			opts: []BootstrapOption{
				WithMetricSinkIdentity("my-proxy", "backplane-0", ""),
			},
			wantHost:     envoyGatewayXdsServerHost,
			wantConns:    defaultEnvoyMaxActiveDownstreamConnections,
			wantIdentity: &MetricSinkIdentity{Proxy: "my-proxy", Replica: "backplane-0"},
		},
		{
			name:      "a nil option is skipped",
			opts:      []BootstrapOption{nil},
			wantHost:  envoyGatewayXdsServerHost,
			wantConns: defaultEnvoyMaxActiveDownstreamConnections,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve(tc.opts...)

			require.NotNil(t, got)
			assert.Equal(t, tc.wantHost, got.XdsServerHost)
			assert.Equal(t, DefaultXdsServerPort, int(got.XdsServerPort))
			require.NotNil(t, got.OverloadMaxActiveDownstreamConnections)
			assert.Equal(t, tc.wantConns, *got.OverloadMaxActiveDownstreamConnections)
			assert.Equal(t, tc.wantIdentity, got.MetricSinkIdentity)
			if tc.wantHeap == nil {
				return
			}
			require.NotNil(t, got.OverloadMaxHeapSizeBytes)
			assert.Equal(t, *tc.wantHeap, *got.OverloadMaxHeapSizeBytes)
		})
	}
}
