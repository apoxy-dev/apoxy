// SPDX-License-Identifier: AGPL-3.0-only

package translator

import (
	"sort"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

const (
	// workerdServiceHeader is the demux header the dispatcher reads
	// (apoxy-cli pkg/workerd/host/dispatcher.js SERVICE_HEADER). Its value is the
	// bare service name: the resident is per-tenant, so the project never travels
	// through Envoy, and the dispatcher resolves the live revision from the service
	// itself — so the revision is deliberately NOT in the header either.
	workerdServiceHeader = "x-apoxy-service"
)

func init() {
	registerHTTPFilter(&workerd{})
}

// workerd is the xDS hook for compute.apoxy.dev Service routes (APO-796). For
// every route the IR marks as workerd-backed it injects the route's project's
// static resident cluster and re-points the route to it while stamping the
// x-apoxy-service demux header with the bare service name. It is stateless:
// the only runtime facts it needs — the resident cluster names and socket
// paths — are pure functions of the route's project owned by
// pkg/workerd/names, and the resident's dispatcher owns all revision and
// liveness demux via /resolve, so a rollout never re-translates xDS. It is a
// no-op when no route is workerd-backed, so it is safe to register
// unconditionally — the shared backplane runs the same in-tree filter chain
// and picks it up automatically.
//
// INVARIANT (load-bearing): a workerd resident serves exactly one project.
// The bare-service header is unambiguous only because of this. In shared
// (multi-project) mode the invariant holds via per-project residents: each
// project's routes carry the project UUID in ir.HTTPRoute.WorkerdProject
// (stamped from the route namespace, which the shared backplane rewrites to
// the multicluster cluster name), and point at that project's own cluster and
// socket ("apoxy-workerd-resident/<uuid>" ->
// ".../apoxy-workerd-resident-<uuid>.in.sock"), so two projects' same-named
// Services land on different residents. Single-project topologies (apoxy dev,
// dedicated mode) leave WorkerdProject empty and keep the legacy bare cluster
// "apoxy-workerd-resident" byte-for-byte. pkg/workerd/names is the single
// owner of this naming scheme; a tenant that fails names.ValidateTenant is
// dropped fail-closed (the route keeps its unroutable placeholder destination
// and 503s) — never re-pointed at another tenant's cluster.
type workerd struct{}

var _ httpFilter = &workerd{}

// patchHCM is a no-op: the demux is route-level (header + cluster), needing no
// HTTP filter in the chain.
func (*workerd) patchHCM(*hcmv3.HttpConnectionManager, *ir.HTTPListener) error {
	return nil
}

// patchResources injects one resident workerd cluster per distinct project
// among this listener's workerd-backed routes. The empty project is a valid
// member: it is the legacy single-project resident cluster. Idempotent across
// listeners and re-translations; deterministic emission order.
func (*workerd) patchResources(tCtx *types.ResourceVersionTable, routes []*ir.HTTPRoute) error {
	tenantSet := make(map[string]struct{})
	for _, r := range routes {
		if r != nil && r.WorkerdService != "" {
			tenantSet[r.WorkerdProject] = struct{}{}
		}
	}
	if len(tenantSet) == 0 {
		return nil
	}
	tenants := make([]string, 0, len(tenantSet))
	for tenant := range tenantSet {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)
	for _, tenant := range tenants {
		// A malformed tenant means a broken upstream invariant (the route
		// namespace was not a project UUID). Fail closed: skip the cluster so
		// the route keeps its unroutable placeholder destination (503) rather
		// than ever landing on another tenant's resident.
		if err := names.ValidateTenant(tenant); err != nil {
			log.Errorf("Skipping workerd resident cluster for invalid tenant: %v", err)
			continue
		}
		clusterName := names.ResidentClusterName(tenant)
		if findXdsCluster(tCtx, clusterName) != nil {
			continue
		}
		socketPath := names.ResidentSocketPath("", tenant)
		// The resident socket is a host AF_UNIX path on the data-plane node, so the
		// cluster reaches it via a Pipe address.
		cluster := &clusterv3.Cluster{
			Name:                 clusterName,
			ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
			LoadAssignment: &endpointv3.ClusterLoadAssignment{
				ClusterName: clusterName,
				Endpoints: []*endpointv3.LocalityLbEndpoints{{
					LbEndpoints: []*endpointv3.LbEndpoint{{
						HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
							Endpoint: &endpointv3.Endpoint{
								Address: &corev3.Address{
									Address: &corev3.Address_Pipe{
										Pipe: &corev3.Pipe{Path: socketPath},
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
		log.Infof("Injected workerd resident cluster %s -> %s", clusterName, socketPath)
	}
	return nil
}

// patchRoute re-points a workerd-backed route to its project's resident
// cluster and sets the x-apoxy-service demux header to the bare service name
// (the resident is per-project, so the project never travels through Envoy;
// the dispatcher resolves the live revision). It is a no-op for non-workerd
// routes and for redirect/direct-response routes (which have no RouteAction to
// re-point).
func (*workerd) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute) error {
	if irRoute == nil || irRoute.WorkerdService == "" {
		return nil
	}
	// A redirect/direct-response route has no RouteAction to re-point.
	action := route.GetRoute()
	if action == nil {
		return nil
	}
	// Fail closed on a malformed tenant: leave the route untouched so it keeps
	// its unroutable placeholder destination (503) instead of ever being
	// re-pointed at another tenant's resident. Return nil so translation of
	// the remaining routes continues.
	if err := names.ValidateTenant(irRoute.WorkerdProject); err != nil {
		log.Errorf("Not re-pointing route %s to a workerd resident: %v", route.GetName(), err)
		return nil
	}
	route.RequestHeadersToAdd = append(route.GetRequestHeadersToAdd(), &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: workerdServiceHeader, Value: irRoute.WorkerdService},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	})
	clusterName := names.ResidentClusterName(irRoute.WorkerdProject)
	action.ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: clusterName}
	log.Infof("Demuxed route %s to workerd resident %s (%s=%s)", route.GetName(), clusterName, workerdServiceHeader, irRoute.WorkerdService)
	return nil
}
