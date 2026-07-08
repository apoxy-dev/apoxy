// SPDX-License-Identifier: AGPL-3.0-only

package translator

import (
	"strings"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
)

// Canonical lowercase project UUIDs, chosen so projectA sorts before projectB
// (the hook emits clusters in sorted-tenant order; "" sorts first).
const (
	projectA = "0a6856fa-0e56-4e1c-b3f1-1e4a49e0a4dd"
	projectB = "7ce458d7-e20c-443c-aeeb-dbc5663c1240"
)

// workerdClusters returns the injected resident clusters in emission order.
// It matches on the resident stem so it needs no reference to the naming
// helpers under test.
func workerdClusters(tCtx *types.ResourceVersionTable) []*clusterv3.Cluster {
	var out []*clusterv3.Cluster
	for _, c := range tCtx.GetXdsResources()[resourcev3.ClusterType] {
		if cl, ok := c.(*clusterv3.Cluster); ok && strings.HasPrefix(cl.GetName(), "apoxy-workerd-resident") {
			out = append(out, cl)
		}
	}
	return out
}

func pipePath(c *clusterv3.Cluster) string {
	return c.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().GetAddress().GetPipe().GetPath()
}

func TestWorkerdPatchResources(t *testing.T) {
	type wantCluster struct {
		name   string
		socket string
	}

	cases := []struct {
		name   string
		routes []*ir.HTTPRoute
		want   []wantCluster
	}{
		{
			// The empty project MUST reproduce the pre-tenancy constants
			// byte-for-byte: single-project topologies already dial these exact
			// strings, so this is the drift guard — assert literals, not names.*.
			name:   "legacy single-project byte compatibility",
			routes: []*ir.HTTPRoute{{Name: "r1", WorkerdService: "echo"}},
			want: []wantCluster{
				{
					name:   "apoxy-workerd-resident",
					socket: "/run/workerd-manager/state/apoxy-workerd-resident.in.sock",
				},
			},
		},
		{
			name: "one cluster per distinct project in sorted order",
			routes: []*ir.HTTPRoute{
				{Name: "rb", WorkerdService: "echo", WorkerdProject: projectB},
				{Name: "ra", WorkerdService: "echo", WorkerdProject: projectA},
				{Name: "rl", WorkerdService: "legacy"},
				{Name: "ra2", WorkerdService: "other", WorkerdProject: projectA},
				{Name: "plain"},
			},
			want: []wantCluster{
				{
					name:   "apoxy-workerd-resident",
					socket: "/run/workerd-manager/state/apoxy-workerd-resident.in.sock",
				},
				{
					name:   "apoxy-workerd-resident/" + projectA,
					socket: "/run/workerd-manager/state/apoxy-workerd-resident-" + projectA + ".in.sock",
				},
				{
					name:   "apoxy-workerd-resident/" + projectB,
					socket: "/run/workerd-manager/state/apoxy-workerd-resident-" + projectB + ".in.sock",
				},
			},
		},
		{
			// A malformed tenant fails closed: no cluster is injected for it and
			// no error is returned, so translation of valid tenants continues.
			name: "invalid tenant is skipped without error",
			routes: []*ir.HTTPRoute{
				{Name: "bad", WorkerdService: "echo", WorkerdProject: "not-a-uuid"},
				{Name: "good", WorkerdService: "echo", WorkerdProject: projectA},
			},
			want: []wantCluster{
				{
					name:   "apoxy-workerd-resident/" + projectA,
					socket: "/run/workerd-manager/state/apoxy-workerd-resident-" + projectA + ".in.sock",
				},
			},
		},
		{
			name:   "no workerd route is a no-op",
			routes: []*ir.HTTPRoute{{Name: "plain"}},
			want:   nil,
		},
		{
			name:   "no routes is a no-op",
			routes: nil,
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tCtx := new(types.ResourceVersionTable)
			if err := (&workerd{}).patchResources(tCtx, tc.routes); err != nil {
				t.Fatalf("patchResources: %v", err)
			}
			got := workerdClusters(tCtx)
			if len(got) != len(tc.want) {
				t.Fatalf("resident cluster count = %d, want %d", len(got), len(tc.want))
			}
			for i, w := range tc.want {
				if got[i].GetName() != w.name {
					t.Errorf("cluster[%d] name = %q, want %q", i, got[i].GetName(), w.name)
				}
				if la := got[i].GetLoadAssignment().GetClusterName(); la != w.name {
					t.Errorf("cluster[%d] load assignment name = %q, want %q", i, la, w.name)
				}
				if p := pipePath(got[i]); p != w.socket {
					t.Errorf("cluster[%d] pipe path = %q, want %q", i, p, w.socket)
				}
			}
		})
	}
}

func TestWorkerdPatchResourcesIdempotent(t *testing.T) {
	tCtx := new(types.ResourceVersionTable)
	routes := []*ir.HTTPRoute{
		{Name: "r1", WorkerdService: "echo"},
		{Name: "r2", WorkerdService: "echo", WorkerdProject: projectA},
	}
	// Two listeners sharing the same tenants call patchResources twice; each
	// tenant's cluster must be injected exactly once.
	for i := 0; i < 2; i++ {
		if err := (&workerd{}).patchResources(tCtx, routes); err != nil {
			t.Fatalf("patchResources #%d: %v", i, err)
		}
	}
	got := workerdClusters(tCtx)
	if len(got) != 2 {
		t.Fatalf("resident cluster count = %d, want 2", len(got))
	}
	if got[0].GetName() == got[1].GetName() {
		t.Fatalf("duplicate resident cluster %q", got[0].GetName())
	}
}

// routeWithAction builds a minimal routed (non-redirect) xDS route pointing at
// the named cluster.
func routeWithAction(name, cluster string) *routev3.Route {
	return &routev3.Route{
		Name: name,
		Action: &routev3.Route_Route{
			Route: &routev3.RouteAction{
				ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: cluster},
			},
		},
	}
}

func headerValue(route *routev3.Route, key string) (string, bool) {
	for _, h := range route.GetRequestHeadersToAdd() {
		if h.GetHeader().GetKey() == key {
			return h.GetHeader().GetValue(), true
		}
	}
	return "", false
}

func TestWorkerdPatchRoute(t *testing.T) {
	cases := []struct {
		name        string
		irRoute     *ir.HTTPRoute
		wantCluster string
		wantHeader  string
	}{
		{
			// The legacy single-project cluster name is asserted as a literal;
			// it is the byte-compat contract with already-deployed topologies.
			name:        "legacy route re-points to the bare resident cluster",
			irRoute:     &ir.HTTPRoute{WorkerdService: "echo"},
			wantCluster: "apoxy-workerd-resident",
			wantHeader:  "echo",
		},
		{
			// The header stays the bare service name even with a project: the
			// project is encoded in the cluster (and thus the socket), never in
			// the header, because each resident already knows its project.
			name:        "project route re-points to its own tenant's cluster",
			irRoute:     &ir.HTTPRoute{WorkerdService: "echo", WorkerdProject: projectA},
			wantCluster: "apoxy-workerd-resident/" + projectA,
			wantHeader:  "echo",
		},
		{
			// Fail closed: a malformed tenant leaves the route on its
			// placeholder destination (503) and returns no error.
			name:    "invalid tenant leaves the route untouched",
			irRoute: &ir.HTTPRoute{WorkerdService: "echo", WorkerdProject: "not-a-uuid"},
		},
		{
			name:    "non-workerd route is untouched",
			irRoute: &ir.HTTPRoute{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route := routeWithAction("httproute/ns/echo/rule/0/match/0", "placeholder-cluster")
			tc.irRoute.Name = route.Name
			if err := (&workerd{}).patchRoute(route, tc.irRoute); err != nil {
				t.Fatalf("patchRoute: %v", err)
			}
			if tc.wantCluster == "" {
				if got := route.GetRoute().GetCluster(); got != "placeholder-cluster" {
					t.Fatalf("route cluster = %q, want untouched placeholder-cluster", got)
				}
				if _, ok := headerValue(route, workerdServiceHeader); ok {
					t.Fatalf("unexpected %s header on untouched route", workerdServiceHeader)
				}
				return
			}
			if got := route.GetRoute().GetCluster(); got != tc.wantCluster {
				t.Fatalf("route cluster = %q, want %q", got, tc.wantCluster)
			}
			v, ok := headerValue(route, workerdServiceHeader)
			if !ok {
				t.Fatalf("missing %s header", workerdServiceHeader)
			}
			if v != tc.wantHeader {
				t.Fatalf("%s = %q, want %q", workerdServiceHeader, v, tc.wantHeader)
			}
		})
	}

	t.Run("redirect route with no action is a no-op", func(t *testing.T) {
		route := &routev3.Route{
			Name:   "httproute/ns/echo/rule/0/match/0",
			Action: &routev3.Route_Redirect{Redirect: &routev3.RedirectAction{}},
		}
		if err := (&workerd{}).patchRoute(route, &ir.HTTPRoute{Name: route.Name, WorkerdService: "echo", WorkerdProject: projectA}); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if _, ok := headerValue(route, workerdServiceHeader); ok {
			t.Fatalf("unexpected %s header on redirect route", workerdServiceHeader)
		}
	})
}
