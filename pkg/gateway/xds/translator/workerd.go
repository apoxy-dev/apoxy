// SPDX-License-Identifier: AGPL-3.0-only

package translator

import (
	"strings"

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
	// "<project>:<service>". The dispatcher resolves the live revision from this
	// key itself, so the revision is deliberately NOT in the header.
	workerdServiceHeader = "x-apoxy-service"
	// workerdResidentSocketPath is the well-known host AF_UNIX path the resident
	// workerd dispatcher listens on, one per data-plane node. It is a hard
	// constant, not a runtime fact: the resident sandbox id is the constant
	// "apoxy-workerd-resident" (pkg/workerd/host.residentSandboxID), the manager's
	// --state_dir defaults to /run/workerd-manager/state (pkg/workerd/manager.run),
	// and the socket is "<state_dir>/<id>.in.sock" (pkg/sandbox.inboundSockPath).
	// In dev the same path is shared into the backplane's Envoy container via the
	// /run/workerd-manager volume mount, so Envoy dials it at the identical path.
	// Overriding --state_dir would break this constant.
	workerdResidentSocketPath = "/run/workerd-manager/state/apoxy-workerd-resident.in.sock"
)

// workerdProjectID, when non-empty, is the project id stamped into the demux
// header for every workerd route, overriding the namespace-derived default. It
// is set once at startup (SetWorkerdProjectID) in single-project topologies —
// `apoxy dev` and the dedicated backplane — where the HTTPRoute namespace is not
// the project id. Left empty (the shared backplane), the project is derived from
// the route's namespace, which there IS the project id. This mirrors the
// backplane extension's tunnelproxy path (`pid := s.projectID; if pid == ""
// { pid = routeNamespace }`).
var workerdProjectID string

// SetWorkerdProjectID installs the static project id the workerd translator hook
// stamps into the demux header, overriding namespace derivation. Call once at
// startup before translation runs; an empty id keeps namespace derivation.
func SetWorkerdProjectID(id string) { workerdProjectID = id }

func init() {
	registerHTTPFilter(&workerd{})
}

// workerd is the xDS hook for compute.apoxy.dev Service routes (APO-796). For
// every route the IR marks as workerd-backed it injects the single static
// resident cluster and re-points the route to it while stamping the
// x-apoxy-service demux header "<project>:<service>". It is stateless: the only
// runtime fact it needs (the resident socket) is a fixed well-known path, and
// the resident's dispatcher owns all revision and liveness demux via /resolve,
// so a rollout never re-translates xDS. It is a no-op when no route is
// workerd-backed, so it is safe to register unconditionally — the shared
// backplane runs the same in-tree filter chain and picks it up automatically.
type workerd struct{}

var _ httpFilter = &workerd{}

// patchHCM is a no-op: the demux is route-level (header + cluster), needing no
// HTTP filter in the chain.
func (*workerd) patchHCM(*hcmv3.HttpConnectionManager, *ir.HTTPListener) error {
	return nil
}

// patchResources injects the single resident workerd cluster when at least one
// route on this listener is workerd-backed. Idempotent across listeners and
// re-translations.
func (*workerd) patchResources(tCtx *types.ResourceVersionTable, routes []*ir.HTTPRoute) error {
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
									Pipe: &corev3.Pipe{Path: workerdResidentSocketPath},
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
	log.Infof("Injected workerd resident cluster %s -> %s", workerdResidentClusterName, workerdResidentSocketPath)
	return nil
}

// patchRoute re-points a workerd-backed route to the resident cluster and sets
// the x-apoxy-service demux header to "<project>:<service>" (the resident's
// dispatcher resolves the live revision). The project is the static override if
// set, else the route's namespace. It is a no-op for non-workerd routes and for
// redirect/direct-response routes (which have no RouteAction to re-point).
func (*workerd) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute) error {
	if irRoute == nil || irRoute.WorkerdService == "" {
		return nil
	}
	// A redirect/direct-response route has no RouteAction to re-point.
	action := route.GetRoute()
	if action == nil {
		return nil
	}
	project := workerdProjectID
	if project == "" {
		project = workerdProjectFromRouteName(route.GetName())
	}
	if project == "" {
		return nil
	}
	header := project + ":" + irRoute.WorkerdService
	route.RequestHeadersToAdd = append(route.GetRequestHeadersToAdd(), &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: workerdServiceHeader, Value: header},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	})
	action.ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: workerdResidentClusterName}
	log.Infof("Demuxed route %s to workerd resident (%s=%s)", route.GetName(), workerdServiceHeader, header)
	return nil
}

// workerdProjectFromRouteName extracts the project id from an Envoy route name.
// IR route names are "httproute/<namespace>/<name>/rule/<idx>/..." (see
// gatewayapi.irRouteName), and on the shared backplane the HTTPRoute namespace
// is the project id. Returns "" if the name is not a parseable httproute name.
func workerdProjectFromRouteName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) < 2 || parts[0] != "httproute" {
		return ""
	}
	return parts[1]
}
