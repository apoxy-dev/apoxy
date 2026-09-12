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
		name      string
		opts      []BootstrapOption
		wantHost  string
		wantHeap  *uint64
		wantConns uint64
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
			if tc.wantHeap == nil {
				return
			}
			require.NotNil(t, got.OverloadMaxHeapSizeBytes)
			assert.Equal(t, *tc.wantHeap, *got.OverloadMaxHeapSizeBytes)
		})
	}
}
