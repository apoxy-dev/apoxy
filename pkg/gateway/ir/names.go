package ir

import (
	"strconv"
	"strings"
)

// routeKindByPrefix maps the lowercased kind that opens an IR route name back
// to the Gateway API kind.
var routeKindByPrefix = map[string]string{
	"httproute": "HTTPRoute",
	"grpcroute": "GRPCRoute",
}

// RouteSource is the Gateway API route object and rule that produced an IR
// HTTPRoute.
type RouteSource struct {
	// Kind is the kind of the route object, such as HTTPRoute.
	Kind string
	// Namespace is the namespace of the route object.
	Namespace string
	// Name is the name of the route object.
	Name string
	// Rule is the index of the rule inside the route object.
	Rule int
}

// ParseRouteName recovers the route object identity from an IR HTTPRoute
// name. The Gateway API translator names every IR route
// "<kind>/<namespace>/<name>/rule/<idx>/match/<idx>", and appends
// "/<hostname>" on the per-host copy, so the first seven segments are the
// identity and anything after them is ignored. Gateway API names are DNS
// labels and cannot hold a "/", so the split is unambiguous. The namespace
// is empty for a route served by a project apiserver. The second
// return is false when the name does not have that shape.
func ParseRouteName(name string) (RouteSource, bool) {
	parts := strings.Split(name, "/")
	if len(parts) < 7 || parts[3] != "rule" || parts[5] != "match" {
		return RouteSource{}, false
	}
	kind, ok := routeKindByPrefix[parts[0]]
	if !ok {
		return RouteSource{}, false
	}
	rule, err := strconv.Atoi(parts[4])
	if err != nil || rule < 0 {
		return RouteSource{}, false
	}
	return RouteSource{Kind: kind, Namespace: parts[1], Name: parts[2], Rule: rule}, true
}

// ListenerSource is the Gateway and listener section that produced an IR
// HTTPListener.
type ListenerSource struct {
	// Namespace is the namespace of the Gateway.
	Namespace string
	// Gateway is the name of the Gateway.
	Gateway string
	// Section is the Gateway listener (section) name.
	Section string
}

// ParseListenerName recovers the Gateway identity from an IR HTTPListener
// name, which the Gateway API translator builds as
// "<namespace>/<gateway>/<section>". The namespace is empty for a Gateway
// served by a project apiserver, which has no namespaces, so only the
// Gateway and section must be present. The second return is false when the
// name does not have that shape.
func ParseListenerName(name string) (ListenerSource, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return ListenerSource{}, false
	}
	return ListenerSource{Namespace: parts[0], Gateway: parts[1], Section: parts[2]}, true
}
