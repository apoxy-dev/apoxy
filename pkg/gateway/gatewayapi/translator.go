// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	KindConfigMap           = "ConfigMap"
	KindClientTrafficPolicy = "ClientTrafficPolicy"
	KindBackendTLSPolicy    = "BackendTLSPolicy"
	KindEnvoyProxy          = "EnvoyProxy"
	KindGateway             = "Gateway"
	KindGatewayClass        = "GatewayClass"
	KindGRPCRoute           = "GRPCRoute"
	KindHTTPRoute           = "HTTPRoute"
	KindNamespace           = "Namespace"
	KindTLSRoute            = "TLSRoute"
	KindTCPRoute            = "TCPRoute"
	KindUDPRoute            = "UDPRoute"
	KindService             = "Service"
	KindServiceImport       = "ServiceImport"
	KindBackend             = "Backend"
	KindEdgeFunction        = "EdgeFunction"
	KindSecret              = "Secret"
	KindSecurityPolicy      = "SecurityPolicy"

	GroupApoxyCore           = "core.apoxy.dev"
	GroupApoxyExtensions     = "extensions.apoxy.dev"
	GroupMultiClusterService = "multicluster.x-k8s.io"

	// OwningGatewayNamespaceLabel is the owner reference label used for managed infra.
	// The value should be the namespace of the accepted Envoy Gateway.
	OwningGatewayNamespaceLabel = "gateway.envoyproxy.io/owning-gateway-namespace"

	OwningGatewayClassLabel = "gateway.envoyproxy.io/owning-gatewayclass"
	// OwningGatewayNameLabel is the owner reference label used for managed infra.
	// The value should be the name of the accepted Envoy Gateway.
	OwningGatewayNameLabel = "gateway.envoyproxy.io/owning-gateway-name"
)

var _ TranslatorManager = (*Translator)(nil)

type TranslatorManager interface {
	Translate(resources *Resources) *TranslateResult
	GetRelevantGateways(gateways []*gwapiv1.Gateway) []*GatewayContext

	RoutesTranslator
	//ListenersTranslator
	//AddressesTranslator
	//FiltersTranslator
}

// Translator translates Gateway API resources to IRs and computes status
// for Gateway API resources.
type Translator struct {
	// GatewayControllerName is the name of the Gateway API controller
	GatewayControllerName string

	// GatewayClassName is the name of the GatewayClass
	// to process Gateways for.
	GatewayClassName gwapiv1.ObjectName

	// GlobalRateLimitEnabled is true when global
	// ratelimiting has been configured by the admin.
	GlobalRateLimitEnabled bool

	// EndpointRoutingDisabled can be set to true to use
	// the Service Cluster IP for routing to the backend
	// instead.
	EndpointRoutingDisabled bool

	// EnvoyPatchPolicyEnabled when the EnvoyPatchPolicy
	// feature is enabled.
	EnvoyPatchPolicyEnabled bool

	// ExtensionGroupKinds stores the group/kind for all resources
	// introduced by an Extension so that the translator can
	// store referenced resources in the IR for later use.
	ExtensionGroupKinds []schema.GroupKind

	// Namespace is the namespace that Envoy Gateway runs in.
	Namespace string
}

type TranslateResult struct {
	Resources
	XdsIR XdsIRMap `json:"xdsIR" yaml:"xdsIR"`
}

func newTranslateResult(gateways []*GatewayContext,
	httpRoutes []*HTTPRouteContext,
	grpcRoutes []*GRPCRouteContext,
	tlsRoutes []*TLSRouteContext,
	tcpRoutes []*TCPRouteContext,
	udpRoutes []*UDPRouteContext,
	xdsIR XdsIRMap) *TranslateResult {
	translateResult := &TranslateResult{
		XdsIR: xdsIR,
	}

	for _, gateway := range gateways {
		translateResult.Gateways = append(translateResult.Gateways, gateway.Gateway)
	}
	for _, httpRoute := range httpRoutes {
		translateResult.HTTPRoutes = append(translateResult.HTTPRoutes, httpRoute.HTTPRoute)
	}
	for _, grpcRoute := range grpcRoutes {
		translateResult.GRPCRoutes = append(translateResult.GRPCRoutes, grpcRoute.GRPCRoute)
	}
	for _, tlsRoute := range tlsRoutes {
		translateResult.TLSRoutes = append(translateResult.TLSRoutes, tlsRoute.TLSRoute)
	}
	for _, tcpRoute := range tcpRoutes {
		translateResult.TCPRoutes = append(translateResult.TCPRoutes, tcpRoute.TCPRoute)
	}
	for _, udpRoute := range udpRoutes {
		translateResult.UDPRoutes = append(translateResult.UDPRoutes, udpRoute.UDPRoute)
	}

	return translateResult
}

func (t *Translator) Translate(resources *Resources) *TranslateResult {
	// Get Gateways belonging to our GatewayClass.
	gateways := t.GetRelevantGateways(resources.Gateways)

	// Build IR maps.
	xdsIR := t.InitIRs(gateways, resources)

	// Process all Listeners for all relevant Gateways.
	t.ProcessListeners(gateways, xdsIR, resources)

	//t.ProcessAddresses(gateways, xdsIR, resources)

	// Process all relevant HTTPRoutes.
	httpRoutes := t.ProcessHTTPRoutes(resources.HTTPRoutes, gateways, resources, xdsIR)

	// Process all relevant GRPCRoutes.
	grpcRoutes := t.ProcessGRPCRoutes(resources.GRPCRoutes, gateways, resources, xdsIR)

	// Process all relevant TLSRoutes.
	tlsRoutes := t.ProcessTLSRoutes(resources.TLSRoutes, gateways, resources, xdsIR)

	// Process all relevant TCPRoutes.
	tcpRoutes := t.ProcessTCPRoutes(resources.TCPRoutes, gateways, resources, xdsIR)

	// Process all relevant UDPRoutes.
	udpRoutes := t.ProcessUDPRoutes(resources.UDPRoutes, gateways, resources, xdsIR)

	// Process BackendTrafficPolicies
	routes := []RouteContext{}
	for _, h := range httpRoutes {
		routes = append(routes, h)
	}
	for _, g := range grpcRoutes {
		routes = append(routes, g)
	}
	for _, t := range tlsRoutes {
		routes = append(routes, t)
	}
	for _, t := range tcpRoutes {
		routes = append(routes, t)
	}
	for _, u := range udpRoutes {
		routes = append(routes, u)
	}

	// Sort xdsIR based on the Gateway API spec
	sortXdsIRMap(xdsIR)

	return newTranslateResult(gateways, httpRoutes, grpcRoutes, tlsRoutes,
		tcpRoutes, udpRoutes, xdsIR)

}

// GetRelevantGateways returns GatewayContexts, containing a copy of the original
// Gateway with the Listener statuses reset.
func (t *Translator) GetRelevantGateways(gateways []*gwapiv1.Gateway) []*GatewayContext {
	var relevant []*GatewayContext

	for _, gateway := range gateways {
		if gateway == nil {
			log.Errorf("nil Gateway in GatewayList")
			continue
		}

		log.Debugf("Checking Gateway %q", gateway.Name)

		if gateway.Spec.GatewayClassName == t.GatewayClassName {
			log.Debugf("Gateway %q is relevant", gateway.Name)
			gc := &GatewayContext{
				Gateway: gateway.DeepCopy(),
			}
			gc.ResetListeners()

			// Set Accepted condition - Gateway is accepted by this controller
			gc.SetCondition(gwapiv1.GatewayConditionAccepted, metav1.ConditionTrue,
				gwapiv1.GatewayReasonAccepted, "Gateway accepted by controller")

			relevant = append(relevant, gc)
		}
	}

	return relevant
}

// InitIRs checks if mergeGateways is enabled in EnvoyProxy config and initializes XdsIR and InfraIR maps with adequate keys.
func (t *Translator) InitIRs(gateways []*GatewayContext, resources *Resources) map[string]*ir.Xds {
	xdsIR := make(XdsIRMap)

	var irKey string
	for _, gateway := range gateways {
		gwXdsIR := &ir.Xds{}
		irKey = t.getIRKey(gateway.Gateway)
		xdsIR[irKey] = gwXdsIR
	}

	return xdsIR
}

// XdsIR extracts IR key from the Gateway object.
func (t *Translator) getIRKey(gw *gwapiv1.Gateway) string {
	if gw.Spec.Infrastructure != nil {
		return gw.Spec.Infrastructure.ParametersRef.Name
	}
	return gw.Name
}
