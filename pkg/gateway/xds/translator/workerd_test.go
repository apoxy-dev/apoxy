// SPDX-License-Identifier: AGPL-3.0-only

package translator

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
)

// fakeWorkerdRegistry is a hand-rolled WorkerdRegistry for the hook tests.
type fakeWorkerdRegistry struct {
	socket string
	demux  map[string]string // service -> "<project>:<service>:<rev>"
}

func (f *fakeWorkerdRegistry) ResidentSocket() string { return f.socket }
func (f *fakeWorkerdRegistry) Active() bool            { return f.socket != "" }
func (f *fakeWorkerdRegistry) DemuxHeader(service string) (string, bool) {
	v, ok := f.demux[service]
	return v, ok
}

// withRegistry installs reg as the process-wide workerd registry for the duration
// of the test and restores the prior value after.
func withRegistry(t *testing.T, reg WorkerdRegistry) {
	t.Helper()
	prev := workerdRegistry
	workerdRegistry = reg
	t.Cleanup(func() { workerdRegistry = prev })
}

func residentClusterCount(tCtx *types.ResourceVersionTable) int {
	n := 0
	for _, c := range tCtx.GetXdsResources()[resourcev3.ClusterType] {
		if cl, ok := c.(*clusterv3.Cluster); ok && cl.GetName() == workerdResidentClusterName {
			n++
		}
	}
	return n
}

func TestWorkerdPatchResources(t *testing.T) {
	workerdRoute := &ir.HTTPRoute{Name: "r1", WorkerdService: "echo"}
	plainRoute := &ir.HTTPRoute{Name: "r2"}

	cases := []struct {
		name      string
		reg       WorkerdRegistry
		routes    []*ir.HTTPRoute
		wantCount int
	}{
		{
			name:      "injects resident cluster for a workerd route",
			reg:       &fakeWorkerdRegistry{socket: "/run/workerd/resident.sock"},
			routes:    []*ir.HTTPRoute{plainRoute, workerdRoute},
			wantCount: 1,
		},
		{
			name:      "no resident published is a no-op",
			reg:       &fakeWorkerdRegistry{socket: ""},
			routes:    []*ir.HTTPRoute{workerdRoute},
			wantCount: 0,
		},
		{
			name:      "no workerd route is a no-op",
			reg:       &fakeWorkerdRegistry{socket: "/run/workerd/resident.sock"},
			routes:    []*ir.HTTPRoute{plainRoute},
			wantCount: 0,
		},
		{
			name:      "nil registry is a no-op",
			reg:       nil,
			routes:    []*ir.HTTPRoute{workerdRoute},
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withRegistry(t, tc.reg)
			tCtx := new(types.ResourceVersionTable)
			if err := (&workerd{}).patchResources(tCtx, tc.routes); err != nil {
				t.Fatalf("patchResources: %v", err)
			}
			if got := residentClusterCount(tCtx); got != tc.wantCount {
				t.Fatalf("resident cluster count = %d, want %d", got, tc.wantCount)
			}
		})
	}
}

func TestWorkerdPatchResourcesIdempotent(t *testing.T) {
	withRegistry(t, &fakeWorkerdRegistry{socket: "/run/workerd/resident.sock"})
	tCtx := new(types.ResourceVersionTable)
	routes := []*ir.HTTPRoute{{Name: "r1", WorkerdService: "echo"}}
	// Two listeners with workerd routes call patchResources twice; the cluster
	// must be injected exactly once.
	for i := 0; i < 2; i++ {
		if err := (&workerd{}).patchResources(tCtx, routes); err != nil {
			t.Fatalf("patchResources #%d: %v", i, err)
		}
	}
	if got := residentClusterCount(tCtx); got != 1 {
		t.Fatalf("resident cluster count = %d, want 1", got)
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
	const socket = "/run/workerd/resident.sock"

	t.Run("re-points and sets demux header for a live workerd route", func(t *testing.T) {
		withRegistry(t, &fakeWorkerdRegistry{
			socket: socket,
			demux:  map[string]string{"echo": "proj-uuid:echo:echo-r1"},
		})
		route := routeWithAction("http/default/route/rule/0/match/0", "http/default/route/rule/0")
		irRoute := &ir.HTTPRoute{Name: route.Name, WorkerdService: "echo"}
		if err := (&workerd{}).patchRoute(route, irRoute); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if got := route.GetRoute().GetCluster(); got != workerdResidentClusterName {
			t.Fatalf("route cluster = %q, want %q", got, workerdResidentClusterName)
		}
		v, ok := headerValue(route, workerdServiceHeader)
		if !ok {
			t.Fatalf("missing %s header", workerdServiceHeader)
		}
		if v != "proj-uuid:echo:echo-r1" {
			t.Fatalf("%s = %q, want proj-uuid:echo:echo-r1", workerdServiceHeader, v)
		}
	})

	t.Run("non-workerd route is untouched", func(t *testing.T) {
		withRegistry(t, &fakeWorkerdRegistry{socket: socket, demux: map[string]string{"echo": "proj:echo:echo-r1"}})
		route := routeWithAction("r", "original-cluster")
		if err := (&workerd{}).patchRoute(route, &ir.HTTPRoute{Name: "r"}); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if got := route.GetRoute().GetCluster(); got != "original-cluster" {
			t.Fatalf("route cluster = %q, want original-cluster", got)
		}
		if _, ok := headerValue(route, workerdServiceHeader); ok {
			t.Fatalf("unexpected %s header on non-workerd route", workerdServiceHeader)
		}
	})

	t.Run("workerd route with no live revision keeps its placeholder", func(t *testing.T) {
		withRegistry(t, &fakeWorkerdRegistry{socket: socket, demux: map[string]string{}})
		route := routeWithAction("r", "placeholder-cluster")
		if err := (&workerd{}).patchRoute(route, &ir.HTTPRoute{Name: "r", WorkerdService: "echo"}); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if got := route.GetRoute().GetCluster(); got != "placeholder-cluster" {
			t.Fatalf("route cluster = %q, want placeholder-cluster", got)
		}
		if _, ok := headerValue(route, workerdServiceHeader); ok {
			t.Fatalf("unexpected %s header when no live revision", workerdServiceHeader)
		}
	})

	t.Run("inactive registry is a no-op", func(t *testing.T) {
		withRegistry(t, &fakeWorkerdRegistry{socket: "", demux: map[string]string{"echo": "proj:echo:echo-r1"}})
		route := routeWithAction("r", "placeholder-cluster")
		if err := (&workerd{}).patchRoute(route, &ir.HTTPRoute{Name: "r", WorkerdService: "echo"}); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if got := route.GetRoute().GetCluster(); got != "placeholder-cluster" {
			t.Fatalf("route cluster = %q, want placeholder-cluster", got)
		}
	})
}
