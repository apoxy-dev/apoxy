// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"testing"

	httpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
)

// dfpClusterArgs builds the xdsClusterArgs that the dynamic forward proxy http
// filter passes to createDynamicForwardProxyCluster for a single Backend.
func dfpClusterArgs(name string, protocol ir.AppProtocol, tls *ir.TLSUpstreamConfig) *xdsClusterArgs {
	return &xdsClusterArgs{
		name: name,
		settings: []*ir.DestinationSetting{
			{
				Protocol:    protocol,
				AddressType: ptr.To(ir.DYNAMIC_PROXY),
				TLS:         tls,
				DynamicForwardProxy: &ir.DynamicForwardProxy{
					Name: name,
				},
			},
		},
	}
}

func TestCreateDynamicForwardProxyCluster_ProtocolOptions(t *testing.T) {
	tests := []struct {
		name      string
		protocol  ir.AppProtocol
		tls       *ir.TLSUpstreamConfig
		wantHTTP2 bool
		wantTLS   bool
	}{
		{
			name:      "h2-over-tls",
			protocol:  ir.HTTP2,
			tls:       &ir.TLSUpstreamConfig{UseSystemTrustStore: true},
			wantHTTP2: true,
			wantTLS:   true,
		},
		{
			name:      "h2c-cleartext",
			protocol:  ir.HTTP2,
			tls:       nil,
			wantHTTP2: true,
			wantTLS:   false,
		},
		{
			name:      "no-protocol-defaults-http1",
			protocol:  ir.HTTP,
			tls:       nil,
			wantHTTP2: false,
			wantTLS:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tCtx := new(types.ResourceVersionTable)
			args := dfpClusterArgs(tc.name, tc.protocol, tc.tls)

			require.NoError(t, createDynamicForwardProxyCluster(args, tCtx))

			cluster := findXdsCluster(tCtx, tc.name)
			require.NotNil(t, cluster, "expected DFP cluster %q to be created", tc.name)

			// TLS transport socket presence mirrors the destination setting.
			if tc.wantTLS {
				require.NotNil(t, cluster.TransportSocket, "expected TLS transport socket")
			} else {
				assert.Nil(t, cluster.TransportSocket, "did not expect TLS transport socket")
			}

			epo := cluster.TypedExtensionProtocolOptions
			if !tc.wantHTTP2 {
				// Without HTTP/2 (or other) options the cluster must carry no typed
				// protocol options so Envoy keeps its HTTP/1.1 upstream default.
				assert.Empty(t, epo, "expected no typed extension protocol options for HTTP/1.1 DFP cluster")
				return
			}

			anyOpts, ok := epo[extensionOptionsKey]
			require.True(t, ok, "expected %s in typed extension protocol options", extensionOptionsKey)

			var hpo httpv3.HttpProtocolOptions
			require.NoError(t, anyOpts.UnmarshalTo(&hpo))

			explicit := hpo.GetExplicitHttpConfig()
			require.NotNil(t, explicit, "expected explicit http config")
			require.NotNil(t, explicit.GetHttp2ProtocolOptions(),
				"expected upstream HTTP/2 protocol options for %s backend", tc.protocol)
		})
	}
}
