// SPDX-License-Identifier: AGPL-3.0-only

package translator

import (
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	// workerdResidentClusterName is the single stable Envoy cluster every
	// workerd-backed Service routes to. The dispatcher inside the resident demuxes
	// by the x-apoxy-service header to the right isolate, so there is one cluster
	// regardless of how many Services/revisions are live.
	workerdResidentClusterName = "apoxy-workerd-resident"
	// workerdServiceHeader is the demux header the dispatcher reads
	// (apoxy-cli pkg/workerd/host/dispatcher.js SERVICE_HEADER). Value format:
	// "<project>:<service>:<revision>".
	workerdServiceHeader = "x-apoxy-service"
)

// WorkerdRegistry is the read view of the routing snapshot the co-located
// workerd-manager publishes (resident socket + per-service live revision). The
// publish receiver (pkg/gateway/workerd.Registry) implements it; tests fake it.
type WorkerdRegistry interface {
	// ResidentSocket returns the host AF_UNIX path the resident dispatcher listens
	// on, or "" if none has been published.
	ResidentSocket() string
	// Active reports whether a resident socket has been published.
	Active() bool
	// DemuxHeader returns the x-apoxy-service header value
	// ("<project>:<service>:<liveRevision>") for a bare compute Service name, or
	// ok=false if the service has no live revision published.
	DemuxHeader(service string) (string, bool)
}

// workerdRegistry is the process-wide published routing snapshot the workerd hook
// reads. It is nil until the apiserver wires the publish channel via
// SetWorkerdRegistry, in which case the hook is inert (no resident, no demux).
var workerdRegistry WorkerdRegistry

// SetWorkerdRegistry installs the published-routing registry the workerd
// translator hook reads. Called once at apiserver startup, before translation
// runs. A nil registry disables workerd routing.
func SetWorkerdRegistry(r WorkerdRegistry) {
	workerdRegistry = r
}

// workerdNotifier is the optional change-signal a registry exposes so the
// xds-translator runner can re-translate when a publish lands after the initial
// translation (the IR bus dedups by value, so it can't carry this signal).
type workerdNotifier interface{ Notify() <-chan struct{} }

// WorkerdRegistryNotify returns the registry's change channel, or nil if no
// registry is installed or it has no change signal. The xds-translator runner
// re-runs translation on each receive so a late publish takes effect.
func WorkerdRegistryNotify() <-chan struct{} {
	if n, ok := workerdRegistry.(workerdNotifier); ok {
		return n.Notify()
	}
	return nil
}

func init() {
	registerHTTPFilter(&workerd{})
}

// workerd is the xDS hook for compute.apoxy.dev Service routes (APO-796). When
// the manager has published a resident socket, it injects the single static
// resident cluster and re-points every workerd-backed route to it while stamping
// the x-apoxy-service demux header. It is a no-op when no resident is published
// or no route is workerd-backed, so it is safe to register unconditionally.
type workerd struct{}

var _ httpFilter = &workerd{}

// patchHCM is a no-op: the demux is route-level (header + cluster), needing no
// HTTP filter in the chain.
func (*workerd) patchHCM(*hcmv3.HttpConnectionManager, *ir.HTTPListener) error {
	return nil
}

// patchResources injects the single resident workerd cluster when a resident is
// published and at least one route on this listener is workerd-backed. Idempotent
// across listeners and re-translations.
func (*workerd) patchResources(tCtx *types.ResourceVersionTable, routes []*ir.HTTPRoute) error {
	if workerdRegistry == nil {
		return nil
	}
	socket := workerdRegistry.ResidentSocket()
	if socket == "" {
		return nil
	}
	needed := false
	for _, r := range routes {
		if r != nil && r.WorkerdService != "" {
			needed = true
			break
		}
	}
	if !needed {
		return nil
	}
	if findXdsCluster(tCtx, workerdResidentClusterName) != nil {
		return nil
	}
	// The resident socket is a host AF_UNIX path on the data-plane node, so the
	// cluster reaches it via a Pipe address.
	cluster := &clusterv3.Cluster{
		Name:                 workerdResidentClusterName,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: workerdResidentClusterName,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: []*endpointv3.LbEndpoint{{
					HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
						Endpoint: &endpointv3.Endpoint{
							Address: &corev3.Address{
								Address: &corev3.Address_Pipe{
									Pipe: &corev3.Pipe{Path: socket},
								},
							},
						},
					},
				}},
			}},
		},
	}
	if err := tCtx.AddXdsResource(resourcev3.ClusterType, cluster); err != nil {
		return err
	}
	log.Infof("Injected workerd resident cluster %s -> %s", workerdResidentClusterName, socket)
	return nil
}

// patchRoute re-points a workerd-backed route to the resident cluster and sets
// the x-apoxy-service demux header to "<project>:<service>:<liveRevision>". It is
// a no-op for non-workerd routes, or when the Service has no live revision yet
// (the route then keeps its placeholder destination and the client sees 503).
func (*workerd) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute) error {
	if irRoute == nil || irRoute.WorkerdService == "" {
		return nil
	}
	if workerdRegistry == nil || !workerdRegistry.Active() {
		return nil
	}
	header, ok := workerdRegistry.DemuxHeader(irRoute.WorkerdService)
	if !ok {
		return nil
	}
	// A redirect/direct-response route has no RouteAction to re-point.
	action := route.GetRoute()
	if action == nil {
		return nil
	}
	route.RequestHeadersToAdd = append(route.GetRequestHeadersToAdd(), &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: workerdServiceHeader, Value: header},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	})
	action.ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: workerdResidentClusterName}
	log.Infof("Demuxed route %s to workerd resident (%s=%s)", route.GetName(), workerdServiceHeader, header)
	return nil
}
