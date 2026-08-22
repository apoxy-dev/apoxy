package telemeta

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestMarkRoute(t *testing.T) {
	cases := []struct {
		name   string
		id     Route
		wantOK bool
	}{
		{
			name:   "full identity",
			id:     Route{Gateway: "prod", Listener: "https", RouteKind: "HTTPRoute", RouteName: "api", RouteRule: "0"},
			wantOK: true,
		},
		{
			name:   "gateway only",
			id:     Route{Gateway: "prod"},
			wantOK: true,
		},
		{
			name:   "zero identity writes nothing",
			id:     Route{},
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &routev3.Route{Name: "test"}
			MarkRoute(r, tc.id)
			got, ok := RouteFrom(r)
			if ok != tc.wantOK {
				t.Fatalf("RouteFrom ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.id {
				t.Fatalf("round-trip = %+v, want %+v", got, tc.id)
			}
		})
	}
	MarkRoute(nil, Route{Gateway: "prod"}) // Must not panic.
}

func TestMarkRouteKeepsOtherFields(t *testing.T) {
	r := &routev3.Route{
		Name: "test",
		Metadata: &corev3.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				FilterMetadataKey: {Fields: map[string]*structpb.Value{
					"project_id": structpb.NewStringValue("proj-1"),
				}},
				"other": {Fields: map[string]*structpb.Value{
					"key": structpb.NewStringValue("value"),
				}},
			},
		},
	}
	MarkRoute(r, Route{Gateway: "prod", Listener: "https"})

	fields := r.GetMetadata().GetFilterMetadata()[FilterMetadataKey].GetFields()
	if got := fields["project_id"].GetStringValue(); got != "proj-1" {
		t.Errorf("project_id = %q, want %q", got, "proj-1")
	}
	if got := fields[FieldGateway].GetStringValue(); got != "prod" {
		t.Errorf("gateway = %q, want %q", got, "prod")
	}
	other := r.GetMetadata().GetFilterMetadata()["other"].GetFields()
	if got := other["key"].GetStringValue(); got != "value" {
		t.Errorf("other namespace = %q, want %q", got, "value")
	}
}

func TestMarkCluster(t *testing.T) {
	cases := []struct {
		name    string
		backend Backend
		wantOK  bool
	}{
		{name: "kind and name", backend: Backend{Kind: "Backend", Name: "api"}, wantOK: true},
		{name: "name only", backend: Backend{Name: "api"}, wantOK: true},
		{name: "zero identity writes nothing", backend: Backend{}, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &clusterv3.Cluster{Name: "test"}
			MarkCluster(c, tc.backend)
			got, ok := ClusterFrom(c)
			if ok != tc.wantOK {
				t.Fatalf("ClusterFrom ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.backend {
				t.Fatalf("round-trip = %+v, want %+v", got, tc.backend)
			}
		})
	}
	MarkCluster(nil, Backend{Kind: "Backend"}) // Must not panic.
}

func TestSetAndReadFields(t *testing.T) {
	c := &clusterv3.Cluster{Name: "test"}
	MarkCluster(c, Backend{Kind: "VPCService", Name: "db"})
	SetClusterField(c, "vpc_network", "default")
	SetClusterField(c, "empty", "")

	if got := ClusterField(c, "vpc_network"); got != "default" {
		t.Errorf("vpc_network = %q, want %q", got, "default")
	}
	if got := ClusterField(c, FieldBackendKind); got != "VPCService" {
		t.Errorf("backend_kind = %q, want %q", got, "VPCService")
	}
	if got := ClusterField(c, "empty"); got != "" {
		t.Errorf("empty = %q, want empty", got)
	}
	if got := ClusterField(&clusterv3.Cluster{}, FieldBackendKind); got != "" {
		t.Errorf("unmarked cluster = %q, want empty", got)
	}

	r := &routev3.Route{Name: "test"}
	SetRouteField(r, "project_id", "proj-1")
	if got := r.GetMetadata().GetFilterMetadata()[FilterMetadataKey].GetFields()["project_id"].GetStringValue(); got != "proj-1" {
		t.Errorf("project_id = %q, want %q", got, "proj-1")
	}
	SetClusterField(nil, "k", "v") // Must not panic.
	SetRouteField(nil, "k", "v")   // Must not panic.
}
