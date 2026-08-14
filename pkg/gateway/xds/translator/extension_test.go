// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"context"
	"testing"

	"github.com/envoyproxy/gateway/proto/extension"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
)

// fakeExtensionClient returns a fixed set of clusters from the
// PostTranslateModify hook.
type fakeExtensionClient struct {
	extension.EnvoyGatewayExtensionClient

	clusters []*clusterv3.Cluster
}

func (c *fakeExtensionClient) PostTranslateModify(
	ctx context.Context,
	req *extension.PostTranslateModifyRequest,
	_ ...grpc.CallOption,
) (*extension.PostTranslateModifyResponse, error) {
	return &extension.PostTranslateModifyResponse{Clusters: c.clusters}, nil
}

func TestProcessExtensionPostTranslateHook(t *testing.T) {
	added := &clusterv3.Cluster{Name: "extension-added-cluster"}

	cases := []struct {
		name string
		tCtx *types.ResourceVersionTable
	}{
		{
			// The translation produced no resources, so the resource
			// map is nil. The hook must not panic on the assignment.
			name: "nil resource map",
			tCtx: &types.ResourceVersionTable{},
		},
		{
			name: "existing clusters",
			tCtx: &types.ResourceVersionTable{
				XdsResources: types.XdsResources{
					resourcev3.ClusterType: {&clusterv3.Cluster{Name: "existing"}},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeExtensionClient{clusters: []*clusterv3.Cluster{added}}
			err := processExtensionPostTranslateHook(context.Background(), tc.tCtx, c)
			require.NoError(t, err)
			got := tc.tCtx.XdsResources[resourcev3.ClusterType]
			require.Len(t, got, 1)
			require.Equal(t, added.Name, got[0].(*clusterv3.Cluster).Name)
		})
	}
}
