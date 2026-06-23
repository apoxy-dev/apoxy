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

// withProjectID installs id as the process-wide static project override for the
// duration of the test and restores the prior value after.
func withProjectID(t *testing.T, id string) {
	t.Helper()
	prev := workerdProjectID
	workerdProjectID = id
	t.Cleanup(func() { workerdProjectID = prev })
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
		routes    []*ir.HTTPRoute
		wantCount int
	}{
		{
			name:      "injects resident cluster for a workerd route",
			routes:    []*ir.HTTPRoute{plainRoute, workerdRoute},
			wantCount: 1,
		},
		{
			name:      "no workerd route is a no-op",
			routes:    []*ir.HTTPRoute{plainRoute},
			wantCount: 0,
		},
		{
			name:      "no routes is a no-op",
			routes:    nil,
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

func TestWorkerdPatchResourcesInjectsConstSocket(t *testing.T) {
	tCtx := new(types.ResourceVersionTable)
	if err := (&workerd{}).patchResources(tCtx, []*ir.HTTPRoute{{Name: "r1", WorkerdService: "echo"}}); err != nil {
		t.Fatalf("patchResources: %v", err)
	}
	var cluster *clusterv3.Cluster
	for _, c := range tCtx.GetXdsResources()[resourcev3.ClusterType] {
		if cl, ok := c.(*clusterv3.Cluster); ok && cl.GetName() == workerdResidentClusterName {
			cluster = cl
		}
	}
	if cluster == nil {
		t.Fatalf("resident cluster not injected")
	}
	got := cluster.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().GetAddress().GetPipe().GetPath()
	if got != workerdResidentSocketPath {
		t.Fatalf("resident cluster pipe path = %q, want %q", got, workerdResidentSocketPath)
	}
}

func TestWorkerdPatchResourcesIdempotent(t *testing.T) {
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
	t.Run("derives project from the route namespace", func(t *testing.T) {
		// No static override: the project is the route name's namespace component
		// (the shared-backplane path, where the HTTPRoute namespace is the project).
		withProjectID(t, "")
		route := routeWithAction("httproute/proj-uuid/echo/rule/0/match/0", "httproute/proj-uuid/echo/rule/0")
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
		// The header carries only the project-qualified service key; the resident
		// resolves the revision.
		if v != "proj-uuid:echo" {
			t.Fatalf("%s = %q, want proj-uuid:echo", workerdServiceHeader, v)
		}
	})

	t.Run("static project override wins over the namespace", func(t *testing.T) {
		// Single-project topologies (apoxy dev, dedicated) set the override because
		// the HTTPRoute namespace is not the project id.
		withProjectID(t, "static-proj")
		route := routeWithAction("httproute/default/echo/rule/0/match/0", "httproute/default/echo/rule/0")
		irRoute := &ir.HTTPRoute{Name: route.Name, WorkerdService: "echo"}
		if err := (&workerd{}).patchRoute(route, irRoute); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if v, _ := headerValue(route, workerdServiceHeader); v != "static-proj:echo" {
			t.Fatalf("%s = %q, want static-proj:echo", workerdServiceHeader, v)
		}
	})

	t.Run("non-workerd route is untouched", func(t *testing.T) {
		withProjectID(t, "static-proj")
		route := routeWithAction("httproute/default/r/rule/0", "original-cluster")
		if err := (&workerd{}).patchRoute(route, &ir.HTTPRoute{Name: route.Name}); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if got := route.GetRoute().GetCluster(); got != "original-cluster" {
			t.Fatalf("route cluster = %q, want original-cluster", got)
		}
		if _, ok := headerValue(route, workerdServiceHeader); ok {
			t.Fatalf("unexpected %s header on non-workerd route", workerdServiceHeader)
		}
	})

	t.Run("unparseable route name with no override is a no-op", func(t *testing.T) {
		withProjectID(t, "")
		route := routeWithAction("not-an-httproute", "placeholder-cluster")
		if err := (&workerd{}).patchRoute(route, &ir.HTTPRoute{Name: "r", WorkerdService: "echo"}); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if got := route.GetRoute().GetCluster(); got != "placeholder-cluster" {
			t.Fatalf("route cluster = %q, want placeholder-cluster", got)
		}
		if _, ok := headerValue(route, workerdServiceHeader); ok {
			t.Fatalf("unexpected %s header when project is unresolved", workerdServiceHeader)
		}
	})

	t.Run("redirect route with no action is a no-op", func(t *testing.T) {
		withProjectID(t, "static-proj")
		route := &routev3.Route{
			Name:   "httproute/default/echo/rule/0/match/0",
			Action: &routev3.Route_Redirect{Redirect: &routev3.RedirectAction{}},
		}
		if err := (&workerd{}).patchRoute(route, &ir.HTTPRoute{Name: route.Name, WorkerdService: "echo"}); err != nil {
			t.Fatalf("patchRoute: %v", err)
		}
		if _, ok := headerValue(route, workerdServiceHeader); ok {
			t.Fatalf("unexpected %s header on redirect route", workerdServiceHeader)
		}
	})
}
