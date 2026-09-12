// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"math"
	"testing"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/bootstrap"
)

const (
	envoyGatewayXdsServerHost = "envoy-gateway"
	xdsClusterName            = "xds_cluster"
)

func TestBuildXdsCluster(t *testing.T) {
	bootstrapXdsCluster := getXdsClusterObjFromBootstrap(t)

	args := &xdsClusterArgs{
		name:         bootstrapXdsCluster.Name,
		tSocket:      bootstrapXdsCluster.TransportSocket,
		endpointType: EndpointTypeDNS,
	}
	dynamicXdsCluster := buildXdsCluster(args)

	require.Equal(t, bootstrapXdsCluster.Name, dynamicXdsCluster.Name)
	require.Equal(t, bootstrapXdsCluster.ClusterDiscoveryType, dynamicXdsCluster.ClusterDiscoveryType)
	require.Equal(t, bootstrapXdsCluster.TransportSocket, dynamicXdsCluster.TransportSocket)
	assert.True(t, proto.Equal(bootstrapXdsCluster.TransportSocket, dynamicXdsCluster.TransportSocket))
	assert.True(t, proto.Equal(bootstrapXdsCluster.ConnectTimeout, dynamicXdsCluster.ConnectTimeout))
}

func TestBuildXdsClusterLoadAssignment(t *testing.T) {
	bootstrapXdsCluster := getXdsClusterObjFromBootstrap(t)
	ds := &ir.DestinationSetting{
		Endpoints: []*ir.DestinationEndpoint{{Host: envoyGatewayXdsServerHost, Port: bootstrap.DefaultXdsServerPort}},
	}
	settings := []*ir.DestinationSetting{ds}
	dynamicXdsClusterLoadAssignment := buildXdsClusterLoadAssignment(bootstrapXdsCluster.Name, settings)

	assert.True(t, proto.Equal(bootstrapXdsCluster.LoadAssignment.Endpoints[0].LbEndpoints[0], dynamicXdsClusterLoadAssignment.Endpoints[0].LbEndpoints[0]))
}

// TestBuildXdsClusterCircuitBreaker checks the thresholds that Envoy receives.
// Envoy caps every limit of a threshold at 1024 unless the limit is written out,
// so each one that the route leaves unset must come out unlimited.
func TestBuildXdsClusterCircuitBreaker(t *testing.T) {
	unlimited := wrapperspb.UInt32(math.MaxUint32)

	cases := []struct {
		name string
		in   *ir.CircuitBreaker
		want *clusterv3.CircuitBreakers_Thresholds
	}{
		{
			name: "nil",
			in:   nil,
			want: &clusterv3.CircuitBreakers_Thresholds{
				Priority:           corev3.RoutingPriority_DEFAULT,
				MaxConnections:     unlimited,
				MaxPendingRequests: unlimited,
				MaxRequests:        unlimited,
				MaxRetries:         wrapperspb.UInt32(1024),
				TrackRemaining:     true,
			},
		},
		{
			name: "only max pending requests",
			in:   &ir.CircuitBreaker{MaxPendingRequests: ptr.To(uint32(64))},
			want: &clusterv3.CircuitBreakers_Thresholds{
				Priority:           corev3.RoutingPriority_DEFAULT,
				MaxConnections:     unlimited,
				MaxPendingRequests: wrapperspb.UInt32(64),
				MaxRequests:        unlimited,
				MaxRetries:         wrapperspb.UInt32(1024),
				TrackRemaining:     true,
			},
		},
		{
			name: "all set",
			in: &ir.CircuitBreaker{
				MaxConnections:      ptr.To(uint32(1)),
				MaxPendingRequests:  ptr.To(uint32(2)),
				MaxParallelRequests: ptr.To(uint32(3)),
				MaxParallelRetries:  ptr.To(uint32(4)),
			},
			want: &clusterv3.CircuitBreakers_Thresholds{
				Priority:           corev3.RoutingPriority_DEFAULT,
				MaxConnections:     wrapperspb.UInt32(1),
				MaxPendingRequests: wrapperspb.UInt32(2),
				MaxRequests:        wrapperspb.UInt32(3),
				MaxRetries:         wrapperspb.UInt32(4),
				TrackRemaining:     true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildXdsClusterCircuitBreaker(tc.in)
			require.Len(t, got.GetThresholds(), 1)
			assert.True(t, proto.Equal(tc.want, got.GetThresholds()[0]),
				"want %v, got %v", tc.want, got.GetThresholds()[0])
		})
	}
}

func getXdsClusterObjFromBootstrap(t *testing.T) *clusterv3.Cluster {
	bootstrapObj := &bootstrapv3.Bootstrap{}
	bootstrapStr, err := bootstrap.GetRenderedBootstrapConfig()
	require.NoError(t, err)
	jsonData, err := yaml.YAMLToJSON([]byte(bootstrapStr))
	require.NoError(t, err)
	err = protojson.Unmarshal(jsonData, bootstrapObj)
	require.NoError(t, err)

	for _, cluster := range bootstrapObj.StaticResources.Clusters {
		if cluster.Name == xdsClusterName {
			return cluster
		}
	}

	return nil
}
