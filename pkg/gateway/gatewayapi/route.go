// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	mcsapi "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi/status"
	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/utils/regex"
	"github.com/apoxy-dev/apoxy/pkg/log"
	apoxynet "github.com/apoxy-dev/apoxy/pkg/net"

	v1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	agwapiv1a1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
)

const (
	// Following the description in `timeout` section of https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto
	// Request timeout, which is defined as Duration, specifies the upstream timeout for the route
	// If not specified, the default is 15s
	HTTPRequestTimeout = "15s"
)

var (
	_                RoutesTranslator = (*Translator)(nil)
	validServiceName                  = `(?i)\.?[a-z_][a-z_0-9]*(\.[a-z_][a-z_0-9]*)*`
	validMethodName                   = `[A-Za-z_][A-Za-z_0-9]*`
)

type RoutesTranslator interface {
	ProcessHTTPRoutes(httpRoutes []*gwapiv1.HTTPRoute, gateways []*GatewayContext, resources *Resources, xdsIR XdsIRMap) []*HTTPRouteContext
	ProcessGRPCRoutes(grpcRoutes []*gwapiv1a2.GRPCRoute, gateways []*GatewayContext, resources *Resources, xdsIR XdsIRMap) []*GRPCRouteContext
	ProcessTLSRoutes(tlsRoutes []*gwapiv1a2.TLSRoute, gateways []*GatewayContext, resources *Resources, xdsIR XdsIRMap) []*TLSRouteContext
	ProcessTCPRoutes(tcpRoutes []*gwapiv1a2.TCPRoute, gateways []*GatewayContext, resources *Resources, xdsIR XdsIRMap) []*TCPRouteContext
	ProcessUDPRoutes(udpRoutes []*gwapiv1a2.UDPRoute, gateways []*GatewayContext, resources *Resources, xdsIR XdsIRMap) []*UDPRouteContext
}

func (t *Translator) ProcessHTTPRoutes(httpRoutes []*gwapiv1.HTTPRoute, gateways []*GatewayContext, resources *Resources, xdsIR XdsIRMap) []*HTTPRouteContext {
	var relevantHTTPRoutes []*HTTPRouteContext

	for _, h := range httpRoutes {
		if h == nil {
			panic("received nil httproute")
		}
		httpRoute := &HTTPRouteContext{
			GatewayControllerName: t.GatewayControllerName,
			HTTPRoute:             h.DeepCopy(),
		}

		log.Debugf("Processing HTTPRoute %q", httpRoute.HTTPRoute.Name)

		// Find out if this route attaches to one of our Gateway's listeners,
		// and if so, get the list of listeners that allow it to attach for each
		// parentRef.
		relevantRoute := t.processAllowedListenersForParentRefs(httpRoute, gateways, resources)
		if !relevantRoute {
			log.Debugf("HTTPRoute %s does not attach to any of the Gateway's Listeners", httpRoute.HTTPRoute.Name)
			continue
		}

		relevantHTTPRoutes = append(relevantHTTPRoutes, httpRoute)

		t.processHTTPRouteParentRefs(httpRoute, resources, xdsIR)
	}

	return relevantHTTPRoutes
}

func (t *Translator) ProcessGRPCRoutes(grpcRoutes []*gwapiv1a2.GRPCRoute, gateways []*GatewayContext, resources *Resources, xdsIR XdsIRMap) []*GRPCRouteContext {
	var relevantGRPCRoutes []*GRPCRouteContext

	for _, g := range grpcRoutes {
		if g == nil {
			panic("received nil grpcroute")
		}
		grpcRoute := &GRPCRouteContext{
			GatewayControllerName: t.GatewayControllerName,
			GRPCRoute:             g.DeepCopy(),
		}

		// Find out if this route attaches to one of our Gateway's listeners,
		// and if so, get the list of listeners that allow it to attach for each
		// parentRef.
		relevantRoute := t.processAllowedListenersForParentRefs(grpcRoute, gateways, resources)
		if !relevantRoute {
			continue
		}

		relevantGRPCRoutes = append(relevantGRPCRoutes, grpcRoute)

		t.processGRPCRouteParentRefs(grpcRoute, resources, xdsIR)
	}

	return relevantGRPCRoutes
}

func (t *Translator) processHTTPRouteParentRefs(httpRoute *HTTPRouteContext, resources *Resources, xdsIR XdsIRMap) {
	log.Infof("Processing HTTPRoute %s", httpRoute.HTTPRoute.Name)
	for _, parentRef := range httpRoute.ParentRefs {
		// Need to compute Route rules within the parentRef loop because
		// any conditions that come out of it have to go on each RouteParentStatus,
		// not on the Route as a whole.
		routeRoutes, err := t.processHTTPRouteRules(httpRoute, parentRef, resources)
		if err != nil {
			log.Errorf("Error processing HTTPRoute rules: %v", err)
			parentRef.SetCondition(httpRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonUnsupportedValue, // TODO: better reason
				status.Error2ConditionMsg(err),
			)
			continue
		}

		// If no negative condition has been set for ResolvedRefs, set "ResolvedRefs=True"
		if !parentRef.HasCondition(httpRoute, gwapiv1.RouteConditionResolvedRefs, metav1.ConditionFalse) {
			log.Infof("Resolved all the Object references for the Route")
			parentRef.SetCondition(httpRoute,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonResolvedRefs,
				"Resolved all the Object references for the Route",
			)
		}

		// Skip parent refs that did not accept the route
		if parentRef.HasCondition(httpRoute, gwapiv1.RouteConditionAccepted, metav1.ConditionFalse) {
			log.Infof("ParentRef did not accept the Route")
			continue
		}

		var hasHostnameIntersection = t.processHTTPRouteParentRefListener(httpRoute, routeRoutes, parentRef, xdsIR)
		if !hasHostnameIntersection {
			log.Infof("No hostname intersections between the HTTPRoute and this parent ref's Listener(s).")
			parentRef.SetCondition(httpRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonNoMatchingListenerHostname,
				"There were no hostname intersections between the HTTPRoute and this parent ref's Listener(s).",
			)
		}

		// If no negative conditions have been set, the route is considered "Accepted=True".
		if parentRef.HTTPRoute != nil &&
			len(parentRef.HTTPRoute.Status.Parents[parentRef.routeParentStatusIdx].Conditions) == 0 {
			log.Infof("Route is accepted")
			parentRef.SetCondition(httpRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonAccepted,
				"Route is accepted",
			)
		}
	}
}

func (t *Translator) processHTTPRouteRules(httpRoute *HTTPRouteContext, parentRef *RouteParentContext, resources *Resources) ([]*ir.HTTPRoute, error) {
	var routeRoutes []*ir.HTTPRoute

	// compute matches, filters, backends
	for ruleIdx, rule := range httpRoute.Spec.Rules {
		httpFiltersContext := t.ProcessHTTPFilters(parentRef, httpRoute, rule.Filters, ruleIdx, resources)

		// A rule is matched if any one of its matches
		// is satisfied (i.e. a logical "OR"), so generate
		// a unique Xds IR HTTPRoute per match.
		ruleRoutes, err := t.processHTTPRouteRule(httpRoute, ruleIdx, httpFiltersContext, rule)
		if err != nil {
			return nil, err
		}

		dstAddrTypeMap := make(map[ir.DestinationAddressType]int)

		var dynamicForwardProxyUsed bool
		for _, backendRef := range rule.BackendRefs {
			ds := t.processDestination(backendRef, parentRef, httpRoute, resources)
			if !t.EndpointRoutingDisabled && ds != nil && len(ds.Endpoints) > 0 && ds.AddressType != nil {
				dstAddrTypeMap[*ds.AddressType]++
			}
			if ds == nil {
				log.Warnf("Skipping destination for backend %s", backendRef.Name)
				continue
			}
			if ds.DynamicForwardProxy != nil {
				log.Debugf("DynamicForwardProxy used for backend %s", backendRef.Name)
				dynamicForwardProxyUsed = true
			}

			for _, route := range ruleRoutes {
				// If the route already has a direct response or redirect configured, then it was from a filter so skip
				// processing any destinations for this route.
				if route.DirectResponse != nil || route.Redirect != nil {
					log.Debugf("Skipping destination for route %s as it has a direct response or redirect configured", route.Name)
					continue
				}

				if route.Destination == nil {
					log.Debugf("Creating destination for route %s", route.Name)
					route.Destination = &ir.RouteDestination{
						Name: irRouteDestinationName(httpRoute, ruleIdx),
					}
				}
				route.Destination.Settings = append(route.Destination.Settings, ds)
			}
		}

		if dynamicForwardProxyUsed && len(rule.BackendRefs) > 1 {
			log.Errorf("DynamicForwardProxy is not supported with multiple destinations")
			routeStatus := GetRouteStatus(httpRoute)
			status.SetRouteStatusCondition(routeStatus,
				parentRef.routeParentStatusIdx,
				httpRoute.GetGeneration(),
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonResolvedRefs,
				"DynamicForwardProxy is not supported with multiple destinations")
		}

		// TODO: support mixed endpointslice address type between backendRefs
		if !t.EndpointRoutingDisabled && len(dstAddrTypeMap) > 1 {
			routeStatus := GetRouteStatus(httpRoute)
			status.SetRouteStatusCondition(routeStatus,
				parentRef.routeParentStatusIdx,
				httpRoute.GetGeneration(),
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonResolvedRefs,
				"Mixed endpointslice address type between backendRefs is not supported")
		}

		// If the route has no valid backends then just use a direct response and don't fuss with weighted responses
		for _, ruleRoute := range ruleRoutes {
			noValidBackends := ruleRoute.Destination == nil || ruleRoute.Destination.ToBackendWeights().Valid == 0
			if noValidBackends && ruleRoute.Redirect == nil {
				log.Errorf("No valid HTTP backends for route %s: destination=%v", ruleRoute.Name, ruleRoute.Destination)
				if ruleRoute.DirectResponse == nil {
					ruleRoute.DirectResponse = &ir.DirectResponse{
						StatusCode: 500,
						Body:       ptr.To("no valid HTTP backends"),
					}
				}
			}
			ruleRoute.IsHTTP2 = false
		}

		// TODO handle:
		//	- sum of weights for valid backend refs is 0
		//	- etc.

		routeRoutes = append(routeRoutes, ruleRoutes...)
	}

	return routeRoutes, nil
}

func processTimeout(irRoute *ir.HTTPRoute, rule gwapiv1.HTTPRouteRule) {
	if rule.Timeouts != nil {
		var rto *ir.Timeout

		// Timeout is translated from multiple resources and may already be partially set
		if irRoute.Timeout != nil {
			rto = irRoute.Timeout.DeepCopy()
		} else {
			rto = &ir.Timeout{}
		}

		if rule.Timeouts.Request != nil {
			d, err := time.ParseDuration(string(*rule.Timeouts.Request))
			if err != nil {
				d, _ = time.ParseDuration(HTTPRequestTimeout)
			}
			setRequestTimeout(rto, metav1.Duration{Duration: d})
		}

		// Also set the IR Route Timeout to the backend request timeout
		// until we introduce retries, then set it to per try timeout
		if rule.Timeouts.BackendRequest != nil {
			d, err := time.ParseDuration(string(*rule.Timeouts.BackendRequest))
			if err != nil {
				d, _ = time.ParseDuration(HTTPRequestTimeout)
			}
			setRequestTimeout(rto, metav1.Duration{Duration: d})
		}

		irRoute.Timeout = rto
	}
}

func setRequestTimeout(irTimeout *ir.Timeout, d metav1.Duration) {
	switch {
	case irTimeout == nil:
		irTimeout = &ir.Timeout{
			HTTP: &ir.HTTPTimeout{
				RequestTimeout: ptr.To(d),
			},
		}
	case irTimeout.HTTP == nil:
		irTimeout.HTTP = &ir.HTTPTimeout{
			RequestTimeout: ptr.To(d),
		}
	default:
		irTimeout.HTTP.RequestTimeout = ptr.To(d)
	}
}

func setTCPKeepalive(irRoute *ir.HTTPRoute, idleTime, interval uint32) {
	// TODO(dilyevsky): Get this setting from the Proxy object. Put in reasonable defaults for now.
	// https://linear.app/apoxy/issue/APO-258/implement-tcpkeepalive-settting
	irRoute.TCPKeepalive = &ir.TCPKeepalive{
		IdleTime: ptr.To(idleTime),
		Interval: ptr.To(interval),
	}
}

func setRetry(irRoute *ir.HTTPRoute, rule gwapiv1.HTTPRouteRule) error {
	if rule.Retry != nil {
		// If this is not nil, defaults are set from:
		// https://github.com/apoxy-dev/apoxy/blob/fcf9377eba517845286065afda7746a8bf1dc076/pkg/gateway/xds/translator/route.go#L105-L106
		irRoute.Retry = &ir.Retry{}

		if len(rule.Retry.Codes) > 0 {
			irRoute.Retry.RetryOn = &ir.RetryOn{}
			for _, code := range rule.Retry.Codes {
				irRoute.Retry.RetryOn.HTTPStatusCodes = append(irRoute.Retry.RetryOn.HTTPStatusCodes, ir.HTTPStatus(code))
			}
		}
		if rule.Retry.Attempts != nil {
			irRoute.Retry.NumRetries = ptr.To(uint32(*rule.Retry.Attempts))
		}
		if rule.Retry.Backoff != nil {
			d, err := time.ParseDuration(string(*rule.Retry.Backoff))
			if err != nil {
				return err
			}
			irRoute.Retry.PerRetry = &ir.PerRetryPolicy{
				BackOff: &ir.BackOffPolicy{
					BaseInterval: &metav1.Duration{
						Duration: d,
					},
				},
			}
		}
	}
	return nil
}

func (t *Translator) processHTTPRouteRule(httpRoute *HTTPRouteContext, ruleIdx int, httpFiltersContext *HTTPFiltersContext, rule gwapiv1.HTTPRouteRule) ([]*ir.HTTPRoute, error) {
	var ruleRoutes []*ir.HTTPRoute

	// If no matches are specified, the implementation MUST match every HTTP request.
	if len(rule.Matches) == 0 {
		irRoute := &ir.HTTPRoute{
			Name: irRouteName(httpRoute, ruleIdx, -1),
		}
		processTimeout(irRoute, rule)
		setTCPKeepalive(irRoute, 30, 10)
		if err := setRetry(irRoute, rule); err != nil {
			return nil, err
		}
		applyHTTPFiltersContextToIRRoute(httpFiltersContext, irRoute)
		ruleRoutes = append(ruleRoutes, irRoute)
	}

	// A rule is matched if any one of its matches
	// is satisfied (i.e. a logical "OR"), so generate
	// a unique Xds IR HTTPRoute per match.
	for matchIdx, match := range rule.Matches {
		irRoute := &ir.HTTPRoute{
			Name: irRouteName(httpRoute, ruleIdx, matchIdx),
		}
		processTimeout(irRoute, rule)
		setTCPKeepalive(irRoute, 30, 10)
		if err := setRetry(irRoute, rule); err != nil {
			return nil, err
		}

		if match.Path != nil {
			switch PathMatchTypeDerefOr(match.Path.Type, gwapiv1.PathMatchPathPrefix) {
			case gwapiv1.PathMatchPathPrefix:
				irRoute.PathMatch = &ir.StringMatch{
					Prefix: match.Path.Value,
				}
			case gwapiv1.PathMatchExact:
				irRoute.PathMatch = &ir.StringMatch{
					Exact: match.Path.Value,
				}
			case gwapiv1.PathMatchRegularExpression:
				if err := regex.Validate(*match.Path.Value); err != nil {
					return nil, err
				}
				irRoute.PathMatch = &ir.StringMatch{
					SafeRegex: match.Path.Value,
				}
			}
		}
		for _, headerMatch := range match.Headers {
			switch HeaderMatchTypeDerefOr(headerMatch.Type, gwapiv1.HeaderMatchExact) {
			case gwapiv1.HeaderMatchExact:
				irRoute.HeaderMatches = append(irRoute.HeaderMatches, &ir.StringMatch{
					Name:  string(headerMatch.Name),
					Exact: ptr.To(headerMatch.Value),
				})
			case gwapiv1.HeaderMatchRegularExpression:
				if err := regex.Validate(headerMatch.Value); err != nil {
					return nil, err
				}
				irRoute.HeaderMatches = append(irRoute.HeaderMatches, &ir.StringMatch{
					Name:      string(headerMatch.Name),
					SafeRegex: ptr.To(headerMatch.Value),
				})
			}
		}
		for _, queryParamMatch := range match.QueryParams {
			switch QueryParamMatchTypeDerefOr(queryParamMatch.Type, gwapiv1.QueryParamMatchExact) {
			case gwapiv1.QueryParamMatchExact:
				irRoute.QueryParamMatches = append(irRoute.QueryParamMatches, &ir.StringMatch{
					Name:  string(queryParamMatch.Name),
					Exact: ptr.To(queryParamMatch.Value),
				})
			case gwapiv1.QueryParamMatchRegularExpression:
				if err := regex.Validate(queryParamMatch.Value); err != nil {
					return nil, err
				}
				irRoute.QueryParamMatches = append(irRoute.QueryParamMatches, &ir.StringMatch{
					Name:      string(queryParamMatch.Name),
					SafeRegex: ptr.To(queryParamMatch.Value),
				})
			}
		}

		if match.Method != nil {
			irRoute.HeaderMatches = append(irRoute.HeaderMatches, &ir.StringMatch{
				Name:  ":method",
				Exact: ptr.To(string(*match.Method)),
			})
		}
		applyHTTPFiltersContextToIRRoute(httpFiltersContext, irRoute)
		ruleRoutes = append(ruleRoutes, irRoute)
	}

	return ruleRoutes, nil
}

func applyHTTPFiltersContextToIRRoute(httpFiltersContext *HTTPFiltersContext, irRoute *ir.HTTPRoute) {
	// Add the redirect filter or direct response that were created earlier to all the irRoutes
	if httpFiltersContext.RedirectResponse != nil {
		irRoute.Redirect = httpFiltersContext.RedirectResponse
	}
	if httpFiltersContext.DirectResponse != nil {
		irRoute.DirectResponse = httpFiltersContext.DirectResponse
	}
	if httpFiltersContext.URLRewrite != nil {
		irRoute.URLRewrite = httpFiltersContext.URLRewrite
	}
	if len(httpFiltersContext.AddRequestHeaders) > 0 {
		irRoute.AddRequestHeaders = httpFiltersContext.AddRequestHeaders
	}
	if len(httpFiltersContext.RemoveRequestHeaders) > 0 {
		irRoute.RemoveRequestHeaders = httpFiltersContext.RemoveRequestHeaders
	}
	if len(httpFiltersContext.AddResponseHeaders) > 0 {
		irRoute.AddResponseHeaders = httpFiltersContext.AddResponseHeaders
	}
	if len(httpFiltersContext.RemoveResponseHeaders) > 0 {
		irRoute.RemoveResponseHeaders = httpFiltersContext.RemoveResponseHeaders
	}
	if httpFiltersContext.Mirrors != nil {
		irRoute.Mirrors = httpFiltersContext.Mirrors
	}

	if len(httpFiltersContext.ExtensionRefs) > 0 {
		irRoute.ExtensionRefs = httpFiltersContext.ExtensionRefs
	}

}

func (t *Translator) processGRPCRouteParentRefs(grpcRoute *GRPCRouteContext, resources *Resources, xdsIR XdsIRMap) {
	for _, parentRef := range grpcRoute.ParentRefs {

		// Need to compute Route rules within the parentRef loop because
		// any conditions that come out of it have to go on each RouteParentStatus,
		// not on the Route as a whole.
		routeRoutes, err := t.processGRPCRouteRules(grpcRoute, parentRef, resources)
		if err != nil {
			parentRef.SetCondition(grpcRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonUnsupportedValue, // TODO: better reason
				status.Error2ConditionMsg(err),
			)
			continue
		}

		// If no negative condition has been set for ResolvedRefs, set "ResolvedRefs=True"
		if !parentRef.HasCondition(grpcRoute, gwapiv1.RouteConditionResolvedRefs, metav1.ConditionFalse) {
			parentRef.SetCondition(grpcRoute,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonResolvedRefs,
				"Resolved all the Object references for the Route",
			)
		}

		if parentRef.HasCondition(grpcRoute, gwapiv1.RouteConditionAccepted, metav1.ConditionFalse) {
			continue
		}
		var hasHostnameIntersection = t.processHTTPRouteParentRefListener(grpcRoute, routeRoutes, parentRef, xdsIR)
		if !hasHostnameIntersection {
			parentRef.SetCondition(grpcRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonNoMatchingListenerHostname,
				"There were no hostname intersections between the GRPCRoute and this parent ref's Listener(s).",
			)
		}

		// If no negative conditions have been set, the route is considered "Accepted=True".
		if parentRef.GRPCRoute != nil &&
			len(parentRef.GRPCRoute.Status.Parents[parentRef.routeParentStatusIdx].Conditions) == 0 {
			parentRef.SetCondition(grpcRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonAccepted,
				"Route is accepted",
			)
		}

	}
}

func (t *Translator) processGRPCRouteRules(grpcRoute *GRPCRouteContext, parentRef *RouteParentContext, resources *Resources) ([]*ir.HTTPRoute, error) {
	var routeRoutes []*ir.HTTPRoute

	// compute matches, filters, backends
	for ruleIdx, rule := range grpcRoute.Spec.Rules {
		httpFiltersContext := t.ProcessGRPCFilters(parentRef, grpcRoute, rule.Filters, resources)

		// A rule is matched if any one of its matches
		// is satisfied (i.e. a logical "OR"), so generate
		// a unique Xds IR HTTPRoute per match.
		ruleRoutes, err := t.processGRPCRouteRule(grpcRoute, ruleIdx, httpFiltersContext, rule)
		if err != nil {
			return nil, err
		}

		for _, backendRef := range rule.BackendRefs {
			backendRef := backendRef
			ds := t.processDestination(backendRef, parentRef, grpcRoute, resources)
			if ds == nil {
				continue
			}

			for _, route := range ruleRoutes {
				// If the route already has a direct response or redirect configured, then it was from a filter so skip
				// processing any destinations for this route.
				if route.DirectResponse != nil || route.Redirect != nil {
					continue
				}

				if route.Destination == nil {
					route.Destination = &ir.RouteDestination{
						Name: irRouteDestinationName(grpcRoute, ruleIdx),
					}
				}
				route.Destination.Settings = append(route.Destination.Settings, ds)
			}
		}

		// If the route has no valid backends then just use a direct response and don't fuss with weighted responses
		for _, ruleRoute := range ruleRoutes {
			noValidBackends := ruleRoute.Destination == nil || ruleRoute.Destination.ToBackendWeights().Valid == 0
			if noValidBackends && ruleRoute.Redirect == nil {
				ruleRoute.DirectResponse = &ir.DirectResponse{
					StatusCode: 500,
					Body:       ptr.To("no valid gRPC backends"),
				}
			}
			ruleRoute.IsHTTP2 = true
		}

		// TODO handle:
		//	- sum of weights for valid backend refs is 0
		//	- etc.

		routeRoutes = append(routeRoutes, ruleRoutes...)
	}

	return routeRoutes, nil
}

func setGRPCRetry(irRoute *ir.HTTPRoute) {
	// If this is not nil, defaults are set from:
	// https://github.com/apoxy-dev/apoxy/blob/fcf9377eba517845286065afda7746a8bf1dc076/pkg/gateway/xds/translator/route.go#L105-L106
	irRoute.Retry = &ir.Retry{}
}

func (t *Translator) processGRPCRouteRule(grpcRoute *GRPCRouteContext, ruleIdx int, httpFiltersContext *HTTPFiltersContext, rule gwapiv1.GRPCRouteRule) ([]*ir.HTTPRoute, error) {
	var ruleRoutes []*ir.HTTPRoute

	// If no matches are specified, the implementation MUST match every gRPC request.
	if len(rule.Matches) == 0 {
		irRoute := &ir.HTTPRoute{
			Name: irRouteName(grpcRoute, ruleIdx, -1),
		}
		setTCPKeepalive(irRoute, 30, 10)
		setGRPCRetry(irRoute)
		applyHTTPFiltersContextToIRRoute(httpFiltersContext, irRoute)
		ruleRoutes = append(ruleRoutes, irRoute)
	}

	// A rule is matched if any one of its matches
	// is satisfied (i.e. a logical "OR"), so generate
	// a unique Xds IR HTTPRoute per match.
	for matchIdx, match := range rule.Matches {
		irRoute := &ir.HTTPRoute{
			Name: irRouteName(grpcRoute, ruleIdx, matchIdx),
		}
		setTCPKeepalive(irRoute, 30, 10)
		setGRPCRetry(irRoute)

		for _, headerMatch := range match.Headers {
			switch GRPCHeaderMatchTypeDerefOr(headerMatch.Type, gwapiv1.GRPCHeaderMatchExact) {
			case gwapiv1.GRPCHeaderMatchExact:
				irRoute.HeaderMatches = append(irRoute.HeaderMatches, &ir.StringMatch{
					Name:  string(headerMatch.Name),
					Exact: ptr.To(headerMatch.Value),
				})
			case gwapiv1.GRPCHeaderMatchRegularExpression:
				if err := regex.Validate(headerMatch.Value); err != nil {
					return nil, err
				}
				irRoute.HeaderMatches = append(irRoute.HeaderMatches, &ir.StringMatch{
					Name:      string(headerMatch.Name),
					SafeRegex: ptr.To(headerMatch.Value),
				})
			}
		}

		if match.Method != nil {
			// GRPC's path is in the form of "/<service>/<method>"
			switch GRPCMethodMatchTypeDerefOr(match.Method.Type, gwapiv1.GRPCMethodMatchExact) {
			case gwapiv1.GRPCMethodMatchExact:
				t.processGRPCRouteMethodExact(match.Method, irRoute)
			case gwapiv1.GRPCMethodMatchRegularExpression:
				if match.Method.Service != nil {
					if err := regex.Validate(*match.Method.Service); err != nil {
						return nil, err
					}
				}
				if match.Method.Method != nil {
					if err := regex.Validate(*match.Method.Method); err != nil {
						return nil, err
					}
				}
				t.processGRPCRouteMethodRegularExpression(match.Method, irRoute)
			}
		}

		ruleRoutes = append(ruleRoutes, irRoute)
		applyHTTPFiltersContextToIRRoute(httpFiltersContext, irRoute)
	}
	return ruleRoutes, nil
}

func (t *Translator) processGRPCRouteMethodExact(method *gwapiv1.GRPCMethodMatch, irRoute *ir.HTTPRoute) {
	switch {
	case method.Service != nil && method.Method != nil:
		irRoute.PathMatch = &ir.StringMatch{
			Exact: ptr.To(fmt.Sprintf("/%s/%s", *method.Service, *method.Method)),
		}
	case method.Method != nil:
		// Use a header match since the PathMatch doesn't support Suffix matching
		irRoute.HeaderMatches = append(irRoute.HeaderMatches, &ir.StringMatch{
			Name:   ":path",
			Suffix: ptr.To(fmt.Sprintf("/%s", *method.Method)),
		})
	case method.Service != nil:
		irRoute.PathMatch = &ir.StringMatch{
			Prefix: ptr.To(fmt.Sprintf("/%s", *method.Service)),
		}
	}
}

func (t *Translator) processGRPCRouteMethodRegularExpression(method *gwapiv1.GRPCMethodMatch, irRoute *ir.HTTPRoute) {
	switch {
	case method.Service != nil && method.Method != nil:
		irRoute.PathMatch = &ir.StringMatch{
			SafeRegex: ptr.To(fmt.Sprintf("/%s/%s", *method.Service, *method.Method)),
		}
	case method.Method != nil:
		irRoute.PathMatch = &ir.StringMatch{
			SafeRegex: ptr.To(fmt.Sprintf("/%s/%s", validServiceName, *method.Method)),
		}
	case method.Service != nil:
		irRoute.PathMatch = &ir.StringMatch{
			SafeRegex: ptr.To(fmt.Sprintf("/%s/%s", *method.Service, validMethodName)),
		}
	}
}

func (t *Translator) processHTTPRouteParentRefListener(route RouteContext, routeRoutes []*ir.HTTPRoute, parentRef *RouteParentContext, xdsIR XdsIRMap) bool {
	var hasHostnameIntersection bool

	for _, listener := range parentRef.listeners {
		log.Debugf("Processing parent listener %q for route %q", listener.Name, route.GetName())
		hosts := computeHosts(GetHostnames(route), listener.Hostname)
		if len(hosts) == 0 {
			continue
		}
		hasHostnameIntersection = true

		var perHostRoutes []*ir.HTTPRoute
		for _, host := range hosts {
			for _, routeRoute := range routeRoutes {
				// If the redirect port is not set, the final redirect port must be derived.
				if routeRoute.Redirect != nil && routeRoute.Redirect.Port == nil {
					redirectPort := uint32(listener.Port)
					// If redirect scheme is not-empty, the redirect post must be the
					// well-known port associated with the redirect scheme.
					if scheme := routeRoute.Redirect.Scheme; scheme != nil {
						switch strings.ToLower(*scheme) {
						case "http":
							redirectPort = 80
						case "https":
							redirectPort = 443
						}
					}
					// If the redirect scheme does not have a well-known port, or
					// if the redirect scheme is empty, the redirect port must be the Gateway Listener port.
					routeRoute.Redirect.Port = &redirectPort
				}
				// Remove dots from the hostname before appending it to the IR Route name
				// since dots are special chars used in stats tag extraction in Envoy
				underscoredHost := strings.ReplaceAll(host, ".", "_")
				hostRoute := &ir.HTTPRoute{
					Name:                  fmt.Sprintf("%s/%s", routeRoute.Name, underscoredHost),
					Hostname:              host,
					PathMatch:             routeRoute.PathMatch,
					HeaderMatches:         routeRoute.HeaderMatches,
					QueryParamMatches:     routeRoute.QueryParamMatches,
					AddRequestHeaders:     routeRoute.AddRequestHeaders,
					RemoveRequestHeaders:  routeRoute.RemoveRequestHeaders,
					AddResponseHeaders:    routeRoute.AddResponseHeaders,
					RemoveResponseHeaders: routeRoute.RemoveResponseHeaders,
					Destination:           routeRoute.Destination,
					Redirect:              routeRoute.Redirect,
					DirectResponse:        routeRoute.DirectResponse,
					URLRewrite:            routeRoute.URLRewrite,
					Mirrors:               routeRoute.Mirrors,
					ExtensionRefs:         routeRoute.ExtensionRefs,
					Timeout:               routeRoute.Timeout,
					Retry:                 routeRoute.Retry,
					IsHTTP2:               routeRoute.IsHTTP2,
					TCPKeepalive:          routeRoute.TCPKeepalive,
				}
				perHostRoutes = append(perHostRoutes, hostRoute)
			}
		}
		irKey := t.getIRKey(listener.gateway)
		irListener := xdsIR[irKey].GetHTTPListener(irListenerName(listener))
		if irListener != nil {
			if GetRouteType(route) == KindGRPCRoute {
				irListener.IsHTTP2 = true
			}
			irListener.Routes = append(irListener.Routes, perHostRoutes...)
		}
	}

	return hasHostnameIntersection
}

func (t *Translator) ProcessTLSRoutes(tlsRoutes []*gwapiv1a2.TLSRoute, gateways []*GatewayContext, resources *Resources, xdsIR XdsIRMap) []*TLSRouteContext {
	var relevantTLSRoutes []*TLSRouteContext

	for _, tls := range tlsRoutes {
		if tls == nil {
			panic("received nil tlsroute")
		}
		tlsRoute := &TLSRouteContext{
			GatewayControllerName: t.GatewayControllerName,
			TLSRoute:              tls.DeepCopy(),
		}

		// Find out if this route attaches to one of our Gateway's listeners,
		// and if so, get the list of listeners that allow it to attach for each
		// parentRef.
		relevantRoute := t.processAllowedListenersForParentRefs(tlsRoute, gateways, resources)
		if !relevantRoute {
			continue
		}

		relevantTLSRoutes = append(relevantTLSRoutes, tlsRoute)

		t.processTLSRouteParentRefs(tlsRoute, resources, xdsIR)
	}

	return relevantTLSRoutes
}

func (t *Translator) processTLSRouteParentRefs(tlsRoute *TLSRouteContext, resources *Resources, xdsIR XdsIRMap) {
	for _, parentRef := range tlsRoute.ParentRefs {

		// Need to compute Route rules within the parentRef loop because
		// any conditions that come out of it have to go on each RouteParentStatus,
		// not on the Route as a whole.
		var destSettings []*ir.DestinationSetting

		// compute backends
		for _, rule := range tlsRoute.Spec.Rules {
			for _, backendRef := range rule.BackendRefs {
				backendRef := backendRef
				ds := t.processDestination(backendRef, parentRef, tlsRoute, resources)
				if ds != nil {
					destSettings = append(destSettings, ds)
				}
			}

			// TODO handle:
			//	- no valid backend refs
			//	- sum of weights for valid backend refs is 0
			//	- returning 500's for invalid backend refs
			//	- etc.
		}

		// If no negative condition has been set for ResolvedRefs, set "ResolvedRefs=True"
		if !parentRef.HasCondition(tlsRoute, gwapiv1.RouteConditionResolvedRefs, metav1.ConditionFalse) {
			parentRef.SetCondition(tlsRoute,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonResolvedRefs,
				"Resolved all the Object references for the Route",
			)
		}

		// Skip parent refs that did not accept the route
		if parentRef.HasCondition(tlsRoute, gwapiv1.RouteConditionAccepted, metav1.ConditionFalse) {
			continue
		}

		var hasHostnameIntersection bool
		for _, listener := range parentRef.listeners {
			hosts := computeHosts(GetHostnames(tlsRoute), listener.Hostname)
			if len(hosts) == 0 {
				continue
			}

			hasHostnameIntersection = true

			irKey := t.getIRKey(listener.gateway)
			gwXdsIR := xdsIR[irKey]

			// Get the existing TCP listener for this listener
			irListener := gwXdsIR.GetTCPListener(irListenerName(listener))
			if irListener != nil {
				// Add the TLS route to the existing listener
				irRoute := &ir.TCPRoute{
					Name: irTCPRouteName(tlsRoute),
					TLS: &ir.TLS{Passthrough: &ir.TLSInspectorConfig{
						SNIs: hosts,
					}},
					Destination: &ir.RouteDestination{
						Name:     irRouteDestinationName(tlsRoute, -1 /*rule index*/),
						Settings: destSettings,
					},
				}
				irListener.Routes = append(irListener.Routes, irRoute)
			}

		}

		if !hasHostnameIntersection {
			parentRef.SetCondition(tlsRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonNoMatchingListenerHostname,
				"There were no hostname intersections between the HTTPRoute and this parent ref's Listener(s).",
			)
		}

		// If no negative conditions have been set, the route is considered "Accepted=True".
		if parentRef.TLSRoute != nil &&
			len(parentRef.TLSRoute.Status.Parents[parentRef.routeParentStatusIdx].Conditions) == 0 {
			parentRef.SetCondition(tlsRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonAccepted,
				"Route is accepted",
			)
		}
	}
}

func (t *Translator) ProcessUDPRoutes(udpRoutes []*gwapiv1a2.UDPRoute, gateways []*GatewayContext, resources *Resources,
	xdsIR XdsIRMap) []*UDPRouteContext {
	var relevantUDPRoutes []*UDPRouteContext

	for _, u := range udpRoutes {
		if u == nil {
			panic("received nil udproute")
		}
		udpRoute := &UDPRouteContext{
			GatewayControllerName: t.GatewayControllerName,
			UDPRoute:              u.DeepCopy(),
		}

		// Find out if this route attaches to one of our Gateway's listeners,
		// and if so, get the list of listeners that allow it to attach for each
		// parentRef.
		relevantRoute := t.processAllowedListenersForParentRefs(udpRoute, gateways, resources)
		if !relevantRoute {
			continue
		}

		relevantUDPRoutes = append(relevantUDPRoutes, udpRoute)

		t.processUDPRouteParentRefs(udpRoute, resources, xdsIR)
	}

	return relevantUDPRoutes
}

func (t *Translator) processUDPRouteParentRefs(udpRoute *UDPRouteContext, resources *Resources, xdsIR XdsIRMap) {
	for _, parentRef := range udpRoute.ParentRefs {
		// Need to compute Route rules within the parentRef loop because
		// any conditions that come out of it have to go on each RouteParentStatus,
		// not on the Route as a whole.
		var destSettings []*ir.DestinationSetting

		// compute backends
		if len(udpRoute.Spec.Rules) != 1 {
			parentRef.SetCondition(udpRoute,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionFalse,
				"InvalidRule",
				"One and only one rule is supported",
			)
			continue
		}

		for _, backendRef := range udpRoute.Spec.Rules[0].BackendRefs {
			ds := t.processDestination(backendRef, parentRef, udpRoute, resources)
			if ds == nil {
				continue
			}

			destSettings = append(destSettings, ds)
		}

		// If no negative condition has been set for ResolvedRefs, set "ResolvedRefs=True"
		if !parentRef.HasCondition(udpRoute, gwapiv1.RouteConditionResolvedRefs, metav1.ConditionFalse) {
			parentRef.SetCondition(udpRoute,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonResolvedRefs,
				"Resolved all the Object references for the Route",
			)
		}

		// Skip parent refs that did not accept the route
		if parentRef.HasCondition(udpRoute, gwapiv1.RouteConditionAccepted, metav1.ConditionFalse) {
			continue
		}

		accepted := false
		for _, listener := range parentRef.listeners {
			// only one route is allowed for a UDP listener
			if listener.AttachedRoutes() > 1 {
				continue
			}
			if !listener.IsReady() {
				continue
			}
			accepted = true

			irKey := t.getIRKey(listener.gateway)

			containerPort := servicePortToContainerPort(int32(listener.Port))
			// Create the UDP Listener while parsing the UDPRoute since
			// the listener directly links to a routeDestination.
			irListener := &ir.UDPListener{
				CoreListenerDetails: ir.CoreListenerDetails{
					Name:    irUDPListenerName(listener, udpRoute),
					Address: "0.0.0.0",
					Port:    uint32(containerPort),
				},
				Destination: &ir.RouteDestination{
					Name:     irRouteDestinationName(udpRoute, -1 /*rule index*/),
					Settings: destSettings,
				},
			}
			gwXdsIR := xdsIR[irKey]
			gwXdsIR.UDP = append(gwXdsIR.UDP, irListener)

		}

		// If no negative conditions have been set, the route is considered "Accepted=True".
		if accepted && parentRef.UDPRoute != nil &&
			len(parentRef.UDPRoute.Status.Parents[parentRef.routeParentStatusIdx].Conditions) == 0 {
			parentRef.SetCondition(udpRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonAccepted,
				"Route is accepted",
			)
		}

		if !accepted {
			parentRef.SetCondition(udpRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonUnsupportedValue,
				"Multiple routes on the same UDP listener",
			)
		}
	}
}

func (t *Translator) ProcessTCPRoutes(tcpRoutes []*gwapiv1a2.TCPRoute, gateways []*GatewayContext, resources *Resources,
	xdsIR XdsIRMap) []*TCPRouteContext {
	var relevantTCPRoutes []*TCPRouteContext

	for _, tcp := range tcpRoutes {
		if tcp == nil {
			panic("received nil tcproute")
		}
		tcpRoute := &TCPRouteContext{
			GatewayControllerName: t.GatewayControllerName,
			TCPRoute:              tcp.DeepCopy(),
		}

		// Find out if this route attaches to one of our Gateway's listeners,
		// and if so, get the list of listeners that allow it to attach for each
		// parentRef.
		relevantRoute := t.processAllowedListenersForParentRefs(tcpRoute, gateways, resources)
		if !relevantRoute {
			continue
		}

		relevantTCPRoutes = append(relevantTCPRoutes, tcpRoute)

		t.processTCPRouteParentRefs(tcpRoute, resources, xdsIR)
	}

	return relevantTCPRoutes
}

func (t *Translator) processTCPRouteParentRefs(tcpRoute *TCPRouteContext, resources *Resources, xdsIR XdsIRMap) {
	for _, parentRef := range tcpRoute.ParentRefs {
		// Need to compute Route rules within the parentRef loop because
		// any conditions that come out of it have to go on each RouteParentStatus,
		// not on the Route as a whole.
		var destSettings []*ir.DestinationSetting

		// compute backends
		if len(tcpRoute.Spec.Rules) != 1 {
			parentRef.SetCondition(tcpRoute,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionFalse,
				"InvalidRule",
				"One and only one rule is supported",
			)
			continue
		}

		for _, backendRef := range tcpRoute.Spec.Rules[0].BackendRefs {
			backendRef := backendRef
			ds := t.processDestination(backendRef, parentRef, tcpRoute, resources)
			if ds == nil {
				continue
			}

			destSettings = append(destSettings, ds)
		}

		// If no negative condition has been set for ResolvedRefs, set "ResolvedRefs=True"
		if !parentRef.HasCondition(tcpRoute, gwapiv1.RouteConditionResolvedRefs, metav1.ConditionFalse) {
			parentRef.SetCondition(tcpRoute,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonResolvedRefs,
				"Resolved all the Object references for the Route",
			)
		}

		// Skip parent refs that did not accept the route
		if parentRef.HasCondition(tcpRoute, gwapiv1.RouteConditionAccepted, metav1.ConditionFalse) {
			continue
		}

		accepted := false
		for _, listener := range parentRef.listeners {
			// only one route is allowed for a TCP listener
			if listener.AttachedRoutes() > 1 {
				continue
			}
			if !listener.IsReady() {
				continue
			}
			accepted = true
			irKey := t.getIRKey(listener.gateway)
			gwXdsIR := xdsIR[irKey]

			// Get the existing TCP listener for this listener
			irListener := gwXdsIR.GetTCPListener(irListenerName(listener))
			if irListener != nil {
				// Add the TCP route to the existing listener
				irRoute := &ir.TCPRoute{
					Name: irTCPRouteName(tcpRoute),
					TLS:  &ir.TLS{Terminate: irTLSConfigs(listener)},
					Destination: &ir.RouteDestination{
						Name:     irRouteDestinationName(tcpRoute, -1 /*rule index*/),
						Settings: destSettings,
					},
				}
				irListener.Routes = append(irListener.Routes, irRoute)
			}

		}

		// If no negative conditions have been set, the route is considered "Accepted=True".
		if accepted && parentRef.TCPRoute != nil &&
			len(parentRef.TCPRoute.Status.Parents[parentRef.routeParentStatusIdx].Conditions) == 0 {
			parentRef.SetCondition(tcpRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionTrue,
				gwapiv1.RouteReasonAccepted,
				"Route is accepted",
			)
		}
		if !accepted {
			parentRef.SetCondition(tcpRoute,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonUnsupportedValue,
				"Multiple routes on the same TCP listener",
			)
		}

	}
}

// processDestination takes a backendRef and translates it into destination setting or sets error statuses and
// returns the weight for the backend so that 500 error responses can be returned for invalid backends in
// the same proportion as the backend would have otherwise received
func (t *Translator) processDestination(
	backendRefContext BackendRefContext,
	parentRef *RouteParentContext,
	route RouteContext,
	resources *Resources,
) (ds *ir.DestinationSetting) {
	routeType := GetRouteType(route)
	weight := uint32(1)
	backendRef := GetBackendRef(backendRefContext)
	if backendRef.Weight != nil {
		weight = uint32(*backendRef.Weight)
	}

	backendNamespace := NamespaceDerefOr(backendRef.Namespace, route.GetNamespace())
	if !t.validateBackendRef(backendRefContext, parentRef, route, resources, backendNamespace, routeType) {
		log.Errorf("Skipping invalid backend %s/%s", backendNamespace, backendRef.Name)
		// return with empty endpoint means the backend is invalid
		return &ir.DestinationSetting{Weight: &weight}
	}

	// Skip processing backends with 0 weight
	if weight == 0 {
		return nil
	}

	var (
		endpoints []*ir.DestinationEndpoint
		addrType  *ir.DestinationAddressType
	)
	protocol := inspectAppProtocolByRouteKind(routeType)
	switch KindDerefOr(backendRef.Kind, KindService) {
	case KindServiceImport:
		serviceImport := resources.GetServiceImport(backendNamespace, string(backendRef.Name))
		var servicePort mcsapi.ServicePort
		for _, port := range serviceImport.Spec.Ports {
			if port.Port == int32(*backendRef.Port) {
				servicePort = port
				break
			}
		}

		if !t.EndpointRoutingDisabled {
			endpointSlices := resources.GetEndpointSlicesForBackend(backendNamespace, string(backendRef.Name), KindDerefOr(backendRef.Kind, KindService))
			endpoints, addrType = getIREndpointsFromEndpointSlices(endpointSlices, servicePort.Name, servicePort.Protocol)
		} else {
			backendIps := resources.GetServiceImport(backendNamespace, string(backendRef.Name)).Spec.IPs
			for _, ip := range backendIps {
				ep := ir.NewDestEndpoint(
					ip,
					uint32(*backendRef.Port))
				endpoints = append(endpoints, ep)
			}
		}

		ds = &ir.DestinationSetting{
			Weight:      &weight,
			Protocol:    protocol,
			Endpoints:   endpoints,
			AddressType: addrType,
		}
	case KindService:
		ds = t.processServiceDestinationSetting(backendRef.BackendObjectReference, backendNamespace, protocol, resources)
		ds.Filters = t.processDestinationFilters(routeType, backendRefContext, parentRef, route, resources)
	case KindBackend:
		log.Infof("Processing backend %s/%s", backendNamespace, backendRef.Name)

		var err error
		ds, err = t.processBackendDestinationSetting(backendRef.BackendObjectReference, resources)
		if err != nil {
			log.Errorf("failed to process backend ref %s: %v", backendRef.Name, err)
			parentRef.SetCondition(route,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionFalse,
				gwapiv1a2.RouteReasonResolvedRefs,
				err.Error())
			return nil
		} else if ds == nil {
			log.Errorf("Backend ref %s not found", backendRef.Name)
			parentRef.SetCondition(route,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionFalse,
				gwapiv1a2.RouteReasonResolvedRefs,
				"Backend not found")
			return nil
		}
		ds.Filters = t.processDestinationFilters(routeType, backendRefContext, parentRef, route, resources)
	case KindEdgeFunction:
		log.Infof("Processing edge function backend ref %s", backendRef.Name)

		var err error
		if ds, err = t.processEdgeFunctionDestinationSetting(backendRef.BackendObjectReference, protocol, resources); err != nil {
			log.Errorf("failed to process edge function backend ref %s: %v", backendRef.Name, err)
			parentRef.SetCondition(route,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionFalse,
				gwapiv1a2.RouteReasonResolvedRefs,
				err.Error())
			return nil
		}
		if ds == nil {
			log.Errorf("Edge function ref %s not found", backendRef.Name)
			parentRef.SetCondition(route,
				gwapiv1.RouteConditionResolvedRefs,
				metav1.ConditionFalse,
				gwapiv1a2.RouteReasonResolvedRefs,
				"Edge function not found")
			return nil
		}

		ds.Filters = t.processDestinationFilters(routeType, backendRefContext, parentRef, route, resources)
	}

	// TODO: support mixed endpointslice address type for the same backendRef
	if !t.EndpointRoutingDisabled && addrType != nil && *addrType == ir.MIXED {
		parentRef.SetCondition(route,
			gwapiv1.RouteConditionResolvedRefs,
			metav1.ConditionFalse,
			gwapiv1a2.RouteReasonResolvedRefs,
			"Mixed endpointslice address type for the same backendRef is not supported")
	}

	ds.Weight = &weight
	return ds
}

func inspectAppProtocolByRouteKind(kind gwapiv1.Kind) ir.AppProtocol {
	switch kind {
	case KindUDPRoute:
		return ir.UDP
	case KindHTTPRoute:
		return ir.HTTP
	case KindTCPRoute:
		return ir.TCP
	case KindGRPCRoute:
		return ir.GRPC
	case KindTLSRoute:
		return ir.HTTPS
	}
	return ir.TCP
}

func (t *Translator) processServiceDestinationSetting(
	backendRef gwapiv1.BackendObjectReference,
	backendNamespace string,
	protocol ir.AppProtocol,
	resources *Resources,
) *ir.DestinationSetting {
	var (
		endpoints []*ir.DestinationEndpoint
		addrType  *ir.DestinationAddressType
	)

	service := resources.GetService(backendNamespace, string(backendRef.Name))
	var servicePort corev1.ServicePort
	for _, port := range service.Spec.Ports {
		if port.Port == int32(*backendRef.Port) {
			servicePort = port
			break
		}
	}

	// support HTTPRouteBackendProtocolH2C/GRPC
	if servicePort.AppProtocol != nil {
		switch *servicePort.AppProtocol {
		case "kubernetes.io/h2c":
			protocol = ir.HTTP2
		case "grpc":
			protocol = ir.GRPC
		}
	}

	// Route to endpoints by default
	if !t.EndpointRoutingDisabled {
		endpointSlices := resources.GetEndpointSlicesForBackend(backendNamespace, string(backendRef.Name), KindDerefOr(backendRef.Kind, KindService))
		endpoints, addrType = getIREndpointsFromEndpointSlices(endpointSlices, servicePort.Name, servicePort.Protocol)
	} else {
		// Fall back to Service ClusterIP routing
		ep := ir.NewDestEndpoint(
			service.Spec.ClusterIP,
			uint32(*backendRef.Port))
		endpoints = append(endpoints, ep)
	}

	return &ir.DestinationSetting{
		Protocol:    protocol,
		Endpoints:   endpoints,
		AddressType: addrType,
	}
}

func getBackendFilters(routeType gwapiv1.Kind, backendRefContext BackendRefContext) (backendFilters any) {
	filters := GetFilters(backendRefContext)
	switch routeType {
	case KindHTTPRoute:
		if len(filters.([]gwapiv1.HTTPRouteFilter)) > 0 {
			return filters.([]gwapiv1.HTTPRouteFilter)
		}
	case KindGRPCRoute:
		if len(filters.([]gwapiv1.GRPCRouteFilter)) > 0 {
			return filters.([]gwapiv1.GRPCRouteFilter)
		}
	}

	return nil
}

func (t *Translator) processDestinationFilters(
	routeType gwapiv1.Kind,
	backendRefContext BackendRefContext,
	parentRef *RouteParentContext,
	route RouteContext,
	resources *Resources,
) *ir.DestinationFilters {
	backendFilters := getBackendFilters(routeType, backendRefContext)
	if backendFilters == nil {
		return nil
	}

	var httpFiltersContext *HTTPFiltersContext
	var destFilters ir.DestinationFilters

	switch filters := backendFilters.(type) {
	case []gwapiv1.HTTPRouteFilter:
		httpFiltersContext = t.ProcessHTTPFilters(parentRef, route, filters, 0, resources)

	case []gwapiv1.GRPCRouteFilter:
		httpFiltersContext = t.ProcessGRPCFilters(parentRef, route, filters, resources)
	}

	if len(httpFiltersContext.AddRequestHeaders) > 0 {
		destFilters.AddRequestHeaders = httpFiltersContext.AddRequestHeaders
	}
	if len(httpFiltersContext.RemoveRequestHeaders) > 0 {
		destFilters.RemoveRequestHeaders = httpFiltersContext.RemoveRequestHeaders
	}
	if len(httpFiltersContext.AddResponseHeaders) > 0 {
		destFilters.AddResponseHeaders = httpFiltersContext.AddResponseHeaders
	}
	if len(httpFiltersContext.RemoveResponseHeaders) > 0 {
		destFilters.RemoveResponseHeaders = httpFiltersContext.RemoveResponseHeaders
	}

	return &destFilters
}

// processAllowedListenersForParentRefs finds out if the route attaches to one of our
// Gateways' listeners, and if so, gets the list of listeners that allow it to
// attach for each parentRef.
func (t *Translator) processAllowedListenersForParentRefs(routeContext RouteContext, gateways []*GatewayContext, resources *Resources) bool {
	var relevantRoute bool

	for _, parentRef := range GetParentReferences(routeContext) {
		log.Debugf("Processing parentRef %q", parentRef.Name)
		isRelevantParentRef, selectedListeners := GetReferencedListeners(parentRef, gateways)

		// Parent ref is not to a Gateway that we control: skip it
		if !isRelevantParentRef {
			log.Debugf("ParentRef %q is not relevant", parentRef.Name)
			continue
		}
		relevantRoute = true

		log.Debugf("ParentRef %q is relevant", parentRef.Name)

		parentRefCtx := GetRouteParentContext(routeContext, parentRef)
		// Reset conditions since they will be recomputed during translation
		parentRefCtx.ResetConditions(routeContext)

		if len(selectedListeners) == 0 {
			log.Debugf("No listeners match this parent ref")
			parentRefCtx.SetCondition(routeContext,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonNoMatchingParent,
				"No listeners match this parent ref",
			)
			continue
		}

		var allowedListeners []*ListenerContext
		for _, listener := range selectedListeners {
			acceptedKind := GetRouteType(routeContext)
			log.Debugf("Checking if listener %q allows kind %q", listener.Name, acceptedKind)
			if listener.AllowsKind(gwapiv1.RouteGroupKind{Group: GroupPtr(agwapiv1a1.GroupName), Kind: acceptedKind}) {
				allowedListeners = append(allowedListeners, listener)
			}
		}

		if len(allowedListeners) == 0 {
			log.Debugf("No listeners included by this parent ref allowed this attachment.")
			parentRefCtx.SetCondition(routeContext,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				gwapiv1.RouteReasonNotAllowedByListeners,
				"No listeners included by this parent ref allowed this attachment.",
			)
			continue
		}

		// Its safe to increment AttachedRoutes since we've found a valid parentRef
		// and the listener allows this Route kind

		// Theoretically there should only be one parent ref per
		// Route that attaches to a given Listener, so fine to just increment here, but we
		// might want to check to ensure we're not double-counting.
		for _, listener := range allowedListeners {
			listener.IncrementAttachedRoutes()
		}

		if !HasReadyListener(selectedListeners) {
			log.Debugf("No ready listeners for this parent ref")
			parentRefCtx.SetCondition(routeContext,
				gwapiv1.RouteConditionAccepted,
				metav1.ConditionFalse,
				"NoReadyListeners",
				"There are no ready listeners for this parent ref",
			)
			continue
		}

		parentRefCtx.SetListeners(allowedListeners...)

		parentRefCtx.SetCondition(routeContext,
			gwapiv1.RouteConditionAccepted,
			metav1.ConditionTrue,
			gwapiv1.RouteReasonAccepted,
			"Route is accepted",
		)

		log.Debugf("Route %v is accepted", routeContext.GetName())
	}
	return relevantRoute
}

func (t *Translator) processBackendDestinationSetting(backendRef gwapiv1.BackendObjectReference, resources *Resources) (*ir.DestinationSetting, error) {
	if backendRef.Port == nil {
		return nil, errors.New("port is required for backend reference")
	}
	backend := resources.GetBackend(string(backendRef.Name))
	if backend == nil {
		return nil, fmt.Errorf("backend %q not found", backendRef.Name)
	}

	var ds ir.DestinationSetting
	if backend.Spec.DynamicProxy != nil {
		ds.AddressType = ptr.To(ir.DYNAMIC_PROXY)
		ds.DynamicForwardProxy = &ir.DynamicForwardProxy{
			Name:              backend.Name,
			DNSLookupFamily:   ir.DNSLookupFamily(backend.Spec.DynamicProxy.DnsCacheConfig.DNSLookupFamily),
			DNSRefreshRate:    backend.Spec.DynamicProxy.DnsCacheConfig.DNSRefreshRate,
			DNSMinRefreshRate: backend.Spec.DynamicProxy.DnsCacheConfig.DNSMinRefreshRate,
			HostTTL:           backend.Spec.DynamicProxy.DnsCacheConfig.HostTTL,
			MaxHosts:          backend.Spec.DynamicProxy.DnsCacheConfig.MaxHosts,
			DNSQueryTimeout:   backend.Spec.DynamicProxy.DnsCacheConfig.DNSQueryTimeout,
		}
	} else {
		var (
			dstEndpoints []*ir.DestinationEndpoint
			dstAddrType  *ir.DestinationAddressType
		)
		addrTypeMap := make(map[ir.DestinationAddressType]int)
		for _, bep := range backend.Spec.Endpoints {
			var host string
			switch {
			case bep.FQDN != "":
				addrTypeMap[ir.FQDN]++
				host = bep.FQDN
			case bep.IP != "":
				ip, err := netip.ParseAddr(bep.IP)
				if err != nil {
					return nil, fmt.Errorf("invalid IP address %q: %v", bep.IP, err)
				}
				if ip.IsUnspecified() {
					return nil, fmt.Errorf("invalid IP address %q: unspecified IP", bep.IP)
				}
				host = ip.String()
			}

			port := int(*backendRef.Port)
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port %d", port)
			}

			dstEndpoints = append(dstEndpoints, &ir.DestinationEndpoint{
				Host: host,
				Port: uint32(port),
			})
		}

		for addrTypeState, addrTypeCounts := range addrTypeMap {
			if addrTypeCounts == len(backend.Spec.Endpoints) {
				dstAddrType = ptr.To(addrTypeState)
				break
			}
		}
		if len(addrTypeMap) > 0 && dstAddrType == nil {
			dstAddrType = ptr.To(ir.MIXED)
		}

		ds.Endpoints = dstEndpoints
		ds.AddressType = dstAddrType
	}

	switch backend.Spec.Protocol {
	case v1alpha2.BackendProtoH2:
		ds.Protocol = ir.HTTP2
		ds.TLS = &ir.TLSUpstreamConfig{
			UseSystemTrustStore: true,
		}
	case v1alpha2.BackendProtoH2C:
		ds.Protocol = ir.HTTP2
	case v1alpha2.BackendProtoTLS:
		ds.Protocol = ir.HTTP
		ds.TLS = &ir.TLSUpstreamConfig{
			UseSystemTrustStore: true,
		}
	}

	return &ds, nil
}

func (t *Translator) processEdgeFunctionDestinationSetting(
	backendRef gwapiv1.BackendObjectReference,
	protocol ir.AppProtocol,
	resources *Resources,
) (*ir.DestinationSetting, error) {
	fun := resources.GetEdgeFunctionBackend(string(backendRef.Name))
	if fun == nil {
		return nil, fmt.Errorf("EdgeFunction %s not found", backendRef.Name)
	}
	var rev *extensionsv1alpha2.EdgeFunctionRevision
	for _, r := range resources.EdgeFunctionRevisions {
		if r.Name == fun.Status.LiveRevision {
			rev = r
			break
		}
	}
	if rev == nil {
		return nil, fmt.Errorf("EdgeFunctionRevision %s not found", rev.Name)
	}

	if rev.Spec.Runtime == nil || rev.Spec.Runtime.Port == nil {
		return nil, fmt.Errorf("invalid runtime configuration for backend function %q", rev.Name)
	}
	port := *rev.Spec.Runtime.Port
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}

	ds := &ir.DestinationSetting{
		Protocol: protocol,
		Endpoints: []*ir.DestinationEndpoint{
			{
				Host: fmt.Sprintf("%s.%s", rev.Name, apoxynet.EdgeFuncDomain),
				Port: uint32(port),
			},
		},
		AddressType: ptr.To(ir.FQDN),
	}

	return ds, nil
}

func getIREndpointsFromEndpointSlices(endpointSlices []*discoveryv1.EndpointSlice, portName string, portProtocol corev1.Protocol) ([]*ir.DestinationEndpoint, *ir.DestinationAddressType) {
	var (
		dstEndpoints []*ir.DestinationEndpoint
		dstAddrType  *ir.DestinationAddressType
	)

	addrTypeMap := make(map[ir.DestinationAddressType]int)
	for _, endpointSlice := range endpointSlices {
		if endpointSlice.AddressType == discoveryv1.AddressTypeFQDN {
			addrTypeMap[ir.FQDN]++
		} else {
			addrTypeMap[ir.IP]++
		}
		endpoints := getIREndpointsFromEndpointSlice(endpointSlice, portName, portProtocol)
		dstEndpoints = append(dstEndpoints, endpoints...)
	}

	for addrTypeState, addrTypeCounts := range addrTypeMap {
		if addrTypeCounts == len(endpointSlices) {
			dstAddrType = ptr.To(addrTypeState)
			break
		}
	}

	if len(addrTypeMap) > 0 && dstAddrType == nil {
		dstAddrType = ptr.To(ir.MIXED)
	}

	return dstEndpoints, dstAddrType
}

func getIREndpointsFromEndpointSlice(endpointSlice *discoveryv1.EndpointSlice, portName string, portProtocol corev1.Protocol) []*ir.DestinationEndpoint {
	var endpoints []*ir.DestinationEndpoint
	for _, endpoint := range endpointSlice.Endpoints {
		for _, endpointPort := range endpointSlice.Ports {
			// Check if the endpoint port matches the service port
			// and if endpoint is Ready
			if *endpointPort.Name == portName &&
				*endpointPort.Protocol == portProtocol &&
				// Unknown state (nil) should be interpreted as Ready, see https://pkg.go.dev/k8s.io/api/discovery/v1#EndpointConditions
				(endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready) {
				for _, address := range endpoint.Addresses {
					ep := ir.NewDestEndpoint(
						address,
						uint32(*endpointPort.Port))
					endpoints = append(endpoints, ep)
				}
			}
		}
	}

	return endpoints
}

func GetTargetBackendReference(backendRef gwapiv1a2.BackendObjectReference) gwapiv1a2.LocalPolicyTargetReferenceWithSectionName {
	ref := gwapiv1a2.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gwapiv1a2.LocalPolicyTargetReference{
			Group: func() gwapiv1a2.Group {
				if backendRef.Group == nil {
					return ""
				}
				return *backendRef.Group
			}(),
			Kind: func() gwapiv1.Kind {
				if backendRef.Kind == nil {
					return "Service"
				}
				return *backendRef.Kind
			}(),
			Name: backendRef.Name,
		},
		SectionName: func() *gwapiv1.SectionName {
			if backendRef.Port != nil {
				return SectionNamePtr(strconv.Itoa(int(*backendRef.Port)))
			}
			return nil
		}(),
	}
	return ref
}
