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
// filter passes to createDynamicForwardProxyCluster for a single Backend, mirroring
// (*dynamicForwardProxy).patchResources.
func dfpClusterArgs(name string, protocol ir.AppProtocol, family ir.DNSLookupFamily, tls *ir.TLSUpstreamConfig) *xdsClusterArgs {
	return &xdsClusterArgs{
		name: name,
		settings: []*ir.DestinationSetting{
			{
				Protocol:    protocol,
				AddressType: ptr.To(ir.DYNAMIC_PROXY),
				TLS:         tls,
				DynamicForwardProxy: &ir.DynamicForwardProxy{
					Name:            name,
					DNSLookupFamily: family,
				},
			},
		},
	}
}

// TestCreateDynamicForwardProxyCluster_ProtocolOptions reproduces the
// NetworkingProd1 dfp-backend-0e058897 rejection and asserts the fix. A
// core.apoxy.dev Backend with
//
//	dynamicProxy: { dnsCacheConfig: { dnsLookupFamily: v4_only } }
//	protocol: h2
//
// translates (api/.../route.go) to a DestinationSetting with Protocol=HTTP2 and a
// system-trust-store upstream TLS config. Once v0.11.22 began emitting
// typed_extension_protocol_options on the DFP cluster (to speak HTTP/2 upstream),
// Envoy's dynamic_forward_proxy cluster factory rejected the cluster:
//
//	"dynamic_forward_proxy cluster must have auto_sni and auto_san_validation true
//	 unless allow_insecure_cluster_options is set."
//
// because Envoy stops auto-injecting those defaults once the cluster carries typed
// HttpProtocolOptions. The cluster must therefore set both fields itself, while
// still honoring HTTP/2 and keeping its TLS transport socket (SAN validation
// preserved, no allow_insecure_cluster_options).
func TestCreateDynamicForwardProxyCluster_ProtocolOptions(t *testing.T) {
	tests := []struct {
		name         string
		clusterName  string
		protocol     ir.AppProtocol
		family       ir.DNSLookupFamily
		tls          *ir.TLSUpstreamConfig
		wantTypedOps bool // expect typed_extension_protocol_options on the cluster
		wantHTTP2    bool
		wantTLS      bool
	}{
		{
			// Exact production repro: dfp-backend-0e058897, protocol h2, v4_only.
			name:         "h2-over-tls-v4only",
			clusterName:  "dfp-backend-0e058897",
			protocol:     ir.HTTP2,
			family:       ir.V4Only,
			tls:          &ir.TLSUpstreamConfig{UseSystemTrustStore: true},
			wantTypedOps: true,
			wantHTTP2:    true,
			wantTLS:      true,
		},
		{
			// h2c (cleartext HTTP/2) is also rejected by the same Envoy check once
			// typed options are present, even without TLS. auto_sni/auto_san_validation
			// are no-ops over cleartext but must still be set.
			name:         "h2c-cleartext",
			clusterName:  "dfp-backend-h2c",
			protocol:     ir.HTTP2,
			family:       ir.Auto,
			tls:          nil,
			wantTypedOps: true,
			wantHTTP2:    true,
			wantTLS:      false,
		},
		{
			// Plain HTTP/1.1 DFP backend emits no typed options, so Envoy keeps its
			// HTTP/1.1 upstream default and auto-injects auto_sni/auto_san_validation.
			name:         "http1-no-typed-options",
			clusterName:  "dfp-backend-http1",
			protocol:     ir.HTTP,
			family:       ir.Auto,
			tls:          nil,
			wantTypedOps: false,
			wantHTTP2:    false,
			wantTLS:      false,
		},
		{
			// protocol: tls (BackendProtoTLS) -> ir.HTTP + system-trust TLS, no HTTP/2.
			// Still emits no typed options, so the cluster relies on Envoy's auto-inject
			// of auto_sni/auto_san_validation onto the legacy field and is not rejected.
			// The TLS transport socket must still be present.
			name:         "tls-http1-no-typed-options",
			clusterName:  "dfp-backend-tls",
			protocol:     ir.HTTP,
			family:       ir.Auto,
			tls:          &ir.TLSUpstreamConfig{UseSystemTrustStore: true},
			wantTypedOps: false,
			wantHTTP2:    false,
			wantTLS:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tCtx := new(types.ResourceVersionTable)
			args := dfpClusterArgs(tc.clusterName, tc.protocol, tc.family, tc.tls)

			require.NoError(t, createDynamicForwardProxyCluster(args, tCtx))

			cluster := findXdsCluster(tCtx, tc.clusterName)
			require.NotNil(t, cluster, "expected DFP cluster %q to be created", tc.clusterName)

			if tc.wantTLS {
				require.NotNil(t, cluster.TransportSocket, "expected upstream TLS transport socket")
			} else {
				assert.Nil(t, cluster.TransportSocket, "did not expect TLS transport socket")
			}

			if !tc.wantTypedOps {
				assert.Empty(t, cluster.TypedExtensionProtocolOptions,
					"expected no typed extension protocol options (Envoy auto-injects auto_sni/auto_san_validation)")
				return
			}

			anyOpts, ok := cluster.TypedExtensionProtocolOptions[extensionOptionsKey]
			require.True(t, ok, "expected %s in typed extension protocol options", extensionOptionsKey)

			var hpo httpv3.HttpProtocolOptions
			require.NoError(t, anyOpts.UnmarshalTo(&hpo))

			if tc.wantHTTP2 {
				require.NotNil(t, hpo.GetExplicitHttpConfig().GetHttp2ProtocolOptions(),
					"expected upstream HTTP/2 protocol options for %s backend", tc.protocol)
			}

			// The contract Envoy's dynamic_forward_proxy factory enforces.
			uhp := hpo.GetUpstreamHttpProtocolOptions()
			require.NotNil(t, uhp, "DFP cluster must set upstream_http_protocol_options")
			assert.True(t, uhp.GetAutoSni(), "auto_sni must be true on the DFP cluster")
			assert.True(t, uhp.GetAutoSanValidation(), "auto_san_validation must be true on the DFP cluster")
		})
	}
}

// TestBuildTypedExtensionProtocolOptions_NonDFP_NoAutoSNI guards the scope of the
// fix: only dynamic forward proxy clusters get auto_sni/auto_san_validation forced
// on. A normal HTTP/2 cluster must be left untouched so its (possibly explicit) SNI
// handling is not silently overridden and SAN validation behavior is unchanged.
func TestBuildTypedExtensionProtocolOptions_NonDFP_NoAutoSNI(t *testing.T) {
	args := &xdsClusterArgs{
		name:     "static-h2",
		settings: []*ir.DestinationSetting{{Protocol: ir.HTTP2}},
	}

	epo := buildTypedExtensionProtocolOptions(args)
	require.Contains(t, epo, extensionOptionsKey)

	var hpo httpv3.HttpProtocolOptions
	require.NoError(t, epo[extensionOptionsKey].UnmarshalTo(&hpo))

	assert.Nil(t, hpo.GetUpstreamHttpProtocolOptions(),
		"non-DFP clusters must not have upstream_http_protocol_options forced on")
}
