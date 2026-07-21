// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package cache

import (
	"fmt"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
)

func cluster(name string, connectTimeoutSeconds int64) *clusterv3.Cluster {
	c := &clusterv3.Cluster{Name: name}
	if connectTimeoutSeconds != 0 {
		c.AltStatName = fmt.Sprintf("alt-%d", connectTimeoutSeconds)
	}
	return c
}

func routeCfg(name string) *routev3.RouteConfiguration {
	return &routev3.RouteConfiguration{Name: name}
}

func TestHashXdsResourcesEquality(t *testing.T) {
	cases := []struct {
		name string
		a, b types.XdsResources
		want bool
	}{
		{
			name: "identical",
			a:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0), cluster("b", 0)}},
			b:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0), cluster("b", 0)}},
			want: true,
		},
		{
			name: "order insensitive",
			a:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0), cluster("b", 0)}},
			b:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("b", 0), cluster("a", 0)}},
			want: true,
		},
		{
			name: "empty type slice equals absent type",
			a:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0)}, resourcev3.RouteType: nil},
			b:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0)}},
			want: true,
		},
		{
			name: "content change detected",
			a:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0)}},
			b:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 1)}},
			want: false,
		},
		{
			name: "added resource detected",
			a:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0)}},
			b:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0), cluster("b", 0)}},
			want: false,
		},
		{
			// NewSnapshot indexes resources by name last-wins, so duplicate
			// identical copies produce the same pushed snapshot as one copy.
			name: "duplicate identical copies equal a single copy",
			a:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0), cluster("a", 0)}},
			b:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0)}},
			want: true,
		},
		{
			name: "content change across duplicate names detected",
			a:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 1), cluster("a", 1)}},
			b:    types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 2), cluster("a", 2)}},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ha, err := hashXdsResources(tc.a)
			if err != nil {
				t.Fatal(err)
			}
			hb, err := hashXdsResources(tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if got := ha.equal(hb); got != tc.want {
				t.Fatalf("equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDiffSummary(t *testing.T) {
	mustHash := func(t *testing.T, res types.XdsResources) resourceHashes {
		t.Helper()
		h, err := hashXdsResources(res)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	cases := []struct {
		name     string
		old, new types.XdsResources
		want     string
	}{
		{
			name: "initial snapshot lists everything as added",
			old:  nil,
			new:  types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0), cluster("b", 0)}},
			want: "Cluster +2(a,b)",
		},
		{
			name: "add remove and modify across types",
			old: types.XdsResources{
				resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0), cluster("b", 0)},
				resourcev3.RouteType:   []cachetypes.Resource{routeCfg("r1")},
			},
			new: types.XdsResources{
				resourcev3.ClusterType: []cachetypes.Resource{cluster("b", 1), cluster("c", 0)},
			},
			want: "Cluster +1(c) -1(a) ~1(b); RouteConfiguration -1(r1)",
		},
		{
			name: "no changes",
			old:  types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0)}},
			new:  types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{cluster("a", 0)}},
			want: "no per-resource changes",
		},
		{
			name: "name list capped at maxDiffNames",
			old:  nil,
			new: types.XdsResources{resourcev3.ClusterType: []cachetypes.Resource{
				cluster("c1", 0), cluster("c2", 0), cluster("c3", 0), cluster("c4", 0), cluster("c5", 0),
				cluster("c6", 0), cluster("c7", 0), cluster("c8", 0), cluster("c9", 0), cluster("c10", 0),
			}},
			want: "Cluster +10(c1,c10,c2,c3,c4,c5,c6,c7,...)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diffSummary(mustHash(t, tc.old), mustHash(t, tc.new))
			if got != tc.want {
				t.Fatalf("diffSummary() = %q, want %q", got, tc.want)
			}
		})
	}
}
