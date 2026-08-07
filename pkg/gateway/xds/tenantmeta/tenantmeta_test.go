package tenantmeta

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
)

func TestMarkAndFromCluster(t *testing.T) {
	cases := []struct {
		name   string
		marker Marker
		wantOK bool
	}{
		{name: "tenant and input-derived", marker: Marker{TenantKey: "proj-1", InputDerived: true}, wantOK: true},
		{name: "input-derived without tenant", marker: Marker{InputDerived: true}, wantOK: true},
		{name: "tenant without input-derived", marker: Marker{TenantKey: "proj-1"}, wantOK: true},
		{name: "zero marker writes nothing", marker: Marker{}, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &clusterv3.Cluster{Name: "test"}
			Mark(c, tc.marker)
			got, ok := FromCluster(c)
			if ok != tc.wantOK {
				t.Fatalf("FromCluster ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.marker {
				t.Fatalf("round-trip = %+v, want %+v", got, tc.marker)
			}
		})
	}
	Mark(nil, Marker{InputDerived: true}) // Must not panic.
}
