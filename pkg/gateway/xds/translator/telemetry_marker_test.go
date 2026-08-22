package translator

import (
	"testing"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/telemeta"
)

// TestBuildXdsClusterBackendMarker pins the telemetry marker on the normal
// cluster builder: a cluster built for a backend object carries the object's
// kind and name, infra clusters stay unmarked.
func TestBuildXdsClusterBackendMarker(t *testing.T) {
	cases := []struct {
		name       string
		backend    telemeta.Backend
		wantMarker bool
	}{
		{name: "backend object", backend: telemeta.Backend{Kind: "Backend", Name: "api"}, wantMarker: true},
		{name: "vpc service", backend: telemeta.Backend{Kind: "VPCService", Name: "db"}, wantMarker: true},
		{name: "infra cluster stays unmarked", wantMarker: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := buildXdsCluster(&xdsClusterArgs{
				name:         "test-cluster",
				endpointType: EndpointTypeDNS,
				backend:      tc.backend,
			})
			got, ok := telemeta.ClusterFrom(cluster)
			if ok != tc.wantMarker {
				t.Fatalf("marker present = %v, want %v", ok, tc.wantMarker)
			}
			if ok && got != tc.backend {
				t.Fatalf("marker = %+v, want %+v", got, tc.backend)
			}
		})
	}
}

// TestDestinationBackend pins the derivation from a route destination: the
// first named backend wins, and a destination with no named backend yields
// no attribution.
func TestDestinationBackend(t *testing.T) {
	cases := []struct {
		name string
		dest *ir.RouteDestination
		want telemeta.Backend
	}{
		{name: "nil destination", dest: nil},
		{
			name: "single backend",
			dest: &ir.RouteDestination{
				Settings: []*ir.DestinationSetting{{BackendKind: "Backend", BackendName: "api"}},
			},
			want: telemeta.Backend{Kind: "Backend", Name: "api"},
		},
		{
			name: "weighted rule takes the first named backend",
			dest: &ir.RouteDestination{
				Settings: []*ir.DestinationSetting{
					{},
					{BackendKind: "VPCService", BackendName: "db"},
					{BackendKind: "Backend", BackendName: "api"},
				},
			},
			want: telemeta.Backend{Kind: "VPCService", Name: "db"},
		},
		{
			name: "no named backend",
			dest: &ir.RouteDestination{Settings: []*ir.DestinationSetting{{}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := destinationBackend(tc.dest); got != tc.want {
				t.Fatalf("destinationBackend = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestRouteIdentity pins that route attribution comes out of the IR names
// and that a name of another shape leaves its half of the identity empty.
func TestRouteIdentity(t *testing.T) {
	cases := []struct {
		name     string
		listener string
		route    string
		want     telemeta.Route
	}{
		{
			name:     "gateway listener and http route",
			listener: "ns/prod/https",
			route:    "httproute/ns/api/rule/1/match/0/www_example_com",
			want:     telemeta.Route{Gateway: "prod", Listener: "https", RouteKind: "HTTPRoute", RouteName: "api", RouteRule: "1"},
		},
		{
			name:     "grpc route",
			listener: "ns/prod/https",
			route:    "grpcroute/ns/echo/rule/0/match/-1",
			want:     telemeta.Route{Gateway: "prod", Listener: "https", RouteKind: "GRPCRoute", RouteName: "echo", RouteRule: "0"},
		},
		{
			name:     "foreign route name",
			listener: "ns/prod/https",
			route:    "something-else",
			want:     telemeta.Route{Gateway: "prod", Listener: "https"},
		},
		{
			name:     "foreign listener name",
			listener: "https",
			route:    "httproute/ns/api/rule/0/match/0",
			want:     telemeta.Route{RouteKind: "HTTPRoute", RouteName: "api", RouteRule: "0"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeIdentity(tc.listener, tc.route); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
