package translator

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/tenantmeta"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
)

// TestBuildXdsClusterTenantMarker pins the marker contract on the normal
// cluster builder: input-derived destinations carry the tenantmeta marker,
// infra clusters stay unmarked.
func TestBuildXdsClusterTenantMarker(t *testing.T) {
	cases := []struct {
		name         string
		tenantKey    string
		inputDerived bool
		wantMarker   bool
	}{
		{name: "input-derived with tenant", tenantKey: "proj-1", inputDerived: true, wantMarker: true},
		{name: "input-derived without tenant (dedicated)", inputDerived: true, wantMarker: true},
		{name: "infra cluster stays unmarked", wantMarker: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := buildXdsCluster(&xdsClusterArgs{
				name:         "test-cluster",
				endpointType: EndpointTypeDNS,
				marker:       tenantmeta.Marker{TenantKey: tc.tenantKey, InputDerived: tc.inputDerived},
			})
			m, ok := tenantmeta.FromCluster(cluster)
			if ok != tc.wantMarker {
				t.Fatalf("marker present = %v, want %v", ok, tc.wantMarker)
			}
			if ok && (m.TenantKey != tc.tenantKey || m.InputDerived != tc.inputDerived) {
				t.Fatalf("marker = %+v, want {%q %v}", m, tc.tenantKey, tc.inputDerived)
			}
		})
	}
}

// TestDestinationMarker pins the derivation from a route destination: the
// input-derived flag is the OR across settings (weighted rules can mix
// kinds).
func TestDestinationMarker(t *testing.T) {
	cases := []struct {
		name             string
		dest             *ir.RouteDestination
		wantTenantKey    string
		wantInputDerived bool
	}{
		{name: "nil destination", dest: nil},
		{
			name: "backend setting",
			dest: &ir.RouteDestination{
				TenantKey: "proj-1",
				Settings:  []*ir.DestinationSetting{{InputDerived: true}},
			},
			wantTenantKey:    "proj-1",
			wantInputDerived: true,
		},
		{
			name: "mixed kinds OR input-derived",
			dest: &ir.RouteDestination{
				Settings: []*ir.DestinationSetting{{}, {InputDerived: true}},
			},
			wantInputDerived: true,
		},
		{
			name: "infra-only settings",
			dest: &ir.RouteDestination{Settings: []*ir.DestinationSetting{{}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := destinationMarker(tc.dest)
			if m.TenantKey != tc.wantTenantKey || m.InputDerived != tc.wantInputDerived {
				t.Fatalf("destinationMarker = %+v, want {%q %v}",
					m, tc.wantTenantKey, tc.wantInputDerived)
			}
		})
	}
}

// TestDynamicForwardProxyClusterTenantMarker pins the marker on the DFP
// custom cluster, which bypasses buildXdsCluster and previously carried no
// tenant attribution at all.
func TestDynamicForwardProxyClusterTenantMarker(t *testing.T) {
	tCtx := new(types.ResourceVersionTable)
	args := &xdsClusterArgs{
		name: "dfp-backend-test",
		settings: []*ir.DestinationSetting{{
			AddressType:  ptr.To(ir.DYNAMIC_PROXY),
			InputDerived: true,
			DynamicForwardProxy: &ir.DynamicForwardProxy{
				Name:            "dfp-backend-test",
				DNSLookupFamily: ir.V4Only,
			},
		}},
		marker: tenantmeta.Marker{TenantKey: "proj-1", InputDerived: true},
	}
	if err := createDynamicForwardProxyCluster(args, tCtx); err != nil {
		t.Fatalf("createDynamicForwardProxyCluster: %v", err)
	}
	var cluster *clusterv3.Cluster
	for _, res := range tCtx.XdsResources[resourcev3.ClusterType] {
		if c := res.(*clusterv3.Cluster); c.Name == "dfp-backend-test" {
			cluster = c
		}
	}
	if cluster == nil {
		t.Fatalf("DFP cluster not in resource table")
	}
	m, ok := tenantmeta.FromCluster(cluster)
	if !ok || m.TenantKey != "proj-1" || !m.InputDerived {
		t.Fatalf("DFP marker = %+v (ok=%v), want {proj-1 true}", m, ok)
	}
	if cluster.GetClusterType().GetName() != "envoy.clusters.dynamic_forward_proxy" {
		t.Fatalf("stamping changed the DFP cluster type")
	}
}
