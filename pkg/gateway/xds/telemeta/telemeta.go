// Package telemeta carries telemetry attribution on translated xDS routes
// and clusters.
//
// The translator knows which Gateway, listener, route object, and backend
// object produced each xDS resource. Consumers (access logs, Envoy stats)
// previously recovered that identity by parsing cluster names. This package
// makes the identity a typed marker on Route.Metadata.FilterMetadata and
// Cluster.Metadata.FilterMetadata, written at translation time, so the
// name-shape contract is no longer load-bearing.
//
// The marker lives under the "apoxy" filter metadata namespace, the same map
// that the backplane extension server fills with project_id, so an access log
// reads every attribute with one formatter: %METADATA(ROUTE:apoxy:<field>)%
// and %METADATA(CLUSTER:apoxy:<field>)%.
package telemeta

import (
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

// FilterMetadataKey is the FilterMetadata namespace holding the marker.
const FilterMetadataKey = "apoxy"

// Field names inside the marker. Each one is an access log formatter path.
const (
	// FieldGateway is the name of the Gateway that serves the route.
	FieldGateway = "gateway"
	// FieldListener is the Gateway listener (section name) that serves the
	// route.
	FieldListener = "listener"
	// FieldRouteKind is the kind of the route object (HTTPRoute, GRPCRoute).
	FieldRouteKind = "route_kind"
	// FieldRouteName is the name of the route object.
	FieldRouteName = "route_name"
	// FieldRouteRule is the index of the rule inside the route object.
	FieldRouteRule = "route_rule"
	// FieldBackendKind is the kind of the backend object behind the cluster.
	FieldBackendKind = "backend_kind"
	// FieldBackendName is the name of the backend object behind the cluster.
	FieldBackendName = "backend_name"
)

// Route is the route identity of one xDS route.
type Route struct {
	// Gateway is the Gateway name. Empty when the translation has no Gateway
	// context.
	Gateway string
	// Listener is the Gateway listener (section) name.
	Listener string
	// RouteKind is the kind of the route object, such as HTTPRoute.
	RouteKind string
	// RouteName is the name of the route object.
	RouteName string
	// RouteRule is the rule index inside the route object, as a decimal
	// string. Kept a string because the marker is a flat string map.
	RouteRule string
}

// Backend is the backend identity of one xDS cluster.
type Backend struct {
	// Kind is the kind of the backend object, such as Backend or VPCService.
	Kind string
	// Name is the name of the backend object.
	Name string
}

// MarkRoute writes the route identity into the route's filter metadata. A
// zero identity writes nothing. Fields that are already present and fields
// written by other producers, such as project_id, are kept.
func MarkRoute(r *routev3.Route, id Route) {
	if r == nil || id == (Route{}) {
		return
	}
	fields := routeFields(r)
	setIfNotEmpty(fields, FieldGateway, id.Gateway)
	setIfNotEmpty(fields, FieldListener, id.Listener)
	setIfNotEmpty(fields, FieldRouteKind, id.RouteKind)
	setIfNotEmpty(fields, FieldRouteName, id.RouteName)
	setIfNotEmpty(fields, FieldRouteRule, id.RouteRule)
}

// RouteFrom reads the route identity back. ok is false when the route carries
// no marker.
func RouteFrom(r *routev3.Route) (id Route, ok bool) {
	md := r.GetMetadata().GetFilterMetadata()[FilterMetadataKey]
	if md == nil {
		return Route{}, false
	}
	f := md.GetFields()
	return Route{
		Gateway:   f[FieldGateway].GetStringValue(),
		Listener:  f[FieldListener].GetStringValue(),
		RouteKind: f[FieldRouteKind].GetStringValue(),
		RouteName: f[FieldRouteName].GetStringValue(),
		RouteRule: f[FieldRouteRule].GetStringValue(),
	}, true
}

// MarkCluster writes the backend identity into the cluster's filter metadata.
// A zero identity writes nothing: an absent key is what identifies a cluster
// that no backend object produced.
func MarkCluster(c *clusterv3.Cluster, b Backend) {
	if c == nil || b == (Backend{}) {
		return
	}
	fields := clusterFields(c)
	setIfNotEmpty(fields, FieldBackendKind, b.Kind)
	setIfNotEmpty(fields, FieldBackendName, b.Name)
}

// ClusterFrom reads the backend identity back. ok is false when the cluster
// carries no marker.
func ClusterFrom(c *clusterv3.Cluster) (b Backend, ok bool) {
	md := c.GetMetadata().GetFilterMetadata()[FilterMetadataKey]
	if md == nil {
		return Backend{}, false
	}
	f := md.GetFields()
	return Backend{
		Kind: f[FieldBackendKind].GetStringValue(),
		Name: f[FieldBackendName].GetStringValue(),
	}, true
}

// SetClusterField writes one field into the cluster's marker. Consumers that
// learn an attribute after translation, such as the VPC network of an EDS
// cluster, use it to extend the same map.
func SetClusterField(c *clusterv3.Cluster, key, value string) {
	if c == nil || key == "" || value == "" {
		return
	}
	clusterFields(c)[key] = structpb.NewStringValue(value)
}

// ClusterField reads one field out of the cluster's marker. It returns an
// empty string when the field is absent.
func ClusterField(c *clusterv3.Cluster, key string) string {
	return c.GetMetadata().GetFilterMetadata()[FilterMetadataKey].GetFields()[key].GetStringValue()
}

// SetRouteField writes one field into the route's marker. Consumers that own
// an attribute the translator does not know, such as project_id, use it to
// extend the same map.
func SetRouteField(r *routev3.Route, key, value string) {
	if r == nil || key == "" || value == "" {
		return
	}
	routeFields(r)[key] = structpb.NewStringValue(value)
}

// routeFields returns the marker's field map, creating the metadata chain
// when it does not exist yet.
func routeFields(r *routev3.Route) map[string]*structpb.Value {
	if r.Metadata == nil {
		r.Metadata = &corev3.Metadata{}
	}
	if r.Metadata.FilterMetadata == nil {
		r.Metadata.FilterMetadata = map[string]*structpb.Struct{}
	}
	return structFields(r.Metadata.FilterMetadata)
}

// clusterFields returns the marker's field map, creating the metadata chain
// when it does not exist yet.
func clusterFields(c *clusterv3.Cluster) map[string]*structpb.Value {
	if c.Metadata == nil {
		c.Metadata = &corev3.Metadata{}
	}
	if c.Metadata.FilterMetadata == nil {
		c.Metadata.FilterMetadata = map[string]*structpb.Struct{}
	}
	return structFields(c.Metadata.FilterMetadata)
}

func structFields(md map[string]*structpb.Struct) map[string]*structpb.Value {
	s := md[FilterMetadataKey]
	if s == nil {
		s = &structpb.Struct{}
		md[FilterMetadataKey] = s
	}
	if s.Fields == nil {
		s.Fields = map[string]*structpb.Value{}
	}
	return s.Fields
}

func setIfNotEmpty(fields map[string]*structpb.Value, key, value string) {
	if value == "" {
		return
	}
	fields[key] = structpb.NewStringValue(value)
}
