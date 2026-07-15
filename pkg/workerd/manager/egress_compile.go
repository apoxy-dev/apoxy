// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	workerdv1 "github.com/apoxy-dev/apoxy/api/workerd/v1"
)

// This file is the pure egress compiler (APO-726): it turns the compute
// egress API objects (Service egress selections, EgressGateways,
// EgressRoutes) into the per-Service wire planes of the ApplyEgress request
// plus the status each object should carry. It is shared by the two
// reconciler halves — the control-plane status reconciler in the project
// apiserver and the per-pod data-plane pusher in workerd-manager — so their
// views of the egress semantics can never drift.

// ServiceEgressInput is one Service's egress selection, resolved by the
// caller: from the live ServiceRevision's template when one is serving
// (enforcement must match what serves), else from the Service template.
type ServiceEgressInput struct {
	// Name is the compute Service name.
	Name string
	// Egress is the selection; nil means no egress block (the project
	// "default" gateway).
	Egress *computev1alpha1.ServiceEgress
}

// ServiceEgressPlan is the compile result for one Service: its wire plane and
// the EgressReady condition the control plane writes.
type ServiceEgressPlan struct {
	// Name is the compute Service name.
	Name string
	// Gateway is the resolved gateway name; empty when egress is disabled.
	Gateway string
	// Ready and Reason/Message carry the EgressReady condition
	// (computev1alpha1.EgressReadyReason*).
	Ready   bool
	Reason  string
	Message string
	// Config is the compiled wire plane pushed to the resident.
	Config *workerdv1.ServiceEgressConfig
}

// GatewayEgressPlan is the compile result for one EgressGateway object: the
// Ready condition and per-listener attachment counts the control plane
// writes. Listener data-plane fields (port, backendAddress) are owned by the
// gateway data-plane materializer and preserved, never computed here.
type GatewayEgressPlan struct {
	Name    string
	Ready   bool
	Reason  string
	Message string
	// AttachedRoutes counts attached EgressRoutes per listener name.
	AttachedRoutes map[string]int32
}

// RouteEgressPlan is the compile result for one EgressRoute: its
// status.parents entries.
type RouteEgressPlan struct {
	Name    string
	Parents []gwapiv1.RouteParentStatus
}

// EgressPlan is one tenant's full compiled egress state.
type EgressPlan struct {
	// Services is sorted by name so pushes are deterministic.
	Services []ServiceEgressPlan
	Gateways []GatewayEgressPlan
	Routes   []RouteEgressPlan
}

// WireConfigs returns the per-Service wire planes for the ApplyEgress push.
func (p *EgressPlan) WireConfigs() []*workerdv1.ServiceEgressConfig {
	configs := make([]*workerdv1.ServiceEgressConfig, 0, len(p.Services))
	for _, s := range p.Services {
		configs = append(configs, s.Config)
	}
	return configs
}

// CompileEgress compiles one tenant's egress state. Inputs are the Services'
// resolved egress selections plus every EgressGateway and EgressRoute in the
// project. It is pure: no client, no I/O.
func CompileEgress(services []ServiceEgressInput, gateways []computev1alpha1.EgressGateway, routes []computev1alpha1.EgressRoute) *EgressPlan {
	gwByName := make(map[string]*computev1alpha1.EgressGateway, len(gateways))
	for i := range gateways {
		gwByName[gateways[i].Name] = &gateways[i]
	}

	plan := &EgressPlan{}

	// Per-gateway compiled artifacts, computed once and shared by every
	// Service that selects the gateway.
	backendsByGw := make(map[string][]*workerdv1.BackendListener, len(gateways))
	rulesByGw := make(map[string][]*workerdv1.EgressRule, len(gateways))
	attachedByGw := make(map[string]map[string]int32, len(gateways))
	for name, gw := range gwByName {
		backendsByGw[name] = compileBackends(gw)
		attachedByGw[name] = make(map[string]int32, len(gw.Spec.Listeners))
		for _, l := range gw.Spec.Listeners {
			attachedByGw[name][l.Name] = 0
		}
	}

	for i := range routes {
		route := &routes[i]
		rp := RouteEgressPlan{Name: route.Name}
		for _, ref := range route.Spec.ParentRefs {
			gwName := string(ref.Name)
			gw := gwByName[gwName]
			accepted := gw != nil
			reason := gwapiv1.RouteReasonAccepted
			message := "attached"
			var listeners []string
			if gw == nil {
				reason = gwapiv1.RouteReasonNoMatchingParent
				message = fmt.Sprintf("EgressGateway %q not found", gwName)
			} else if ref.SectionName != nil {
				section := string(*ref.SectionName)
				if _, ok := attachedByGw[gwName][section]; !ok {
					accepted = false
					reason = gwapiv1.RouteReasonNoMatchingParent
					message = fmt.Sprintf("EgressGateway %q has no listener %q", gwName, section)
				} else {
					listeners = []string{section}
				}
			}
			if accepted {
				if len(listeners) == 0 {
					// No sectionName: attached to every listener.
					for l := range attachedByGw[gwName] {
						attachedByGw[gwName][l]++
					}
				} else {
					for _, l := range listeners {
						attachedByGw[gwName][l]++
					}
				}
				rulesByGw[gwName] = append(rulesByGw[gwName], compileRules(route, listeners)...)
			}
			rp.Parents = append(rp.Parents, gwapiv1.RouteParentStatus{
				ParentRef:      ref,
				ControllerName: computev1alpha1.EgressControllerName,
				Conditions: []metav1.Condition{
					{
						Type:    string(gwapiv1.RouteConditionAccepted),
						Status:  conditionStatus(accepted),
						Reason:  string(reason),
						Message: message,
					},
				},
			})
		}
		plan.Routes = append(plan.Routes, rp)
	}

	for name, gw := range gwByName {
		gp := GatewayEgressPlan{Name: name, AttachedRoutes: attachedByGw[name]}
		gp.Ready, gp.Reason, gp.Message = gatewayReadiness(gw)
		plan.Gateways = append(plan.Gateways, gp)
	}
	sort.Slice(plan.Gateways, func(i, j int) bool { return plan.Gateways[i].Name < plan.Gateways[j].Name })

	for _, in := range services {
		plan.Services = append(plan.Services, compileService(in, gwByName, backendsByGw, rulesByGw))
	}
	sort.Slice(plan.Services, func(i, j int) bool { return plan.Services[i].Name < plan.Services[j].Name })

	return plan
}

// compileService resolves one Service's egress selection against the compiled
// gateways.
func compileService(in ServiceEgressInput, gwByName map[string]*computev1alpha1.EgressGateway, backendsByGw map[string][]*workerdv1.BackendListener, rulesByGw map[string][]*workerdv1.EgressRule) ServiceEgressPlan {
	if in.Egress != nil && in.Egress.Disabled {
		return ServiceEgressPlan{
			Name:    in.Name,
			Ready:   true,
			Reason:  computev1alpha1.EgressReadyReasonDisabled,
			Message: "egress.disabled: all egress is hard-denied",
			Config: &workerdv1.ServiceEgressConfig{
				Service: in.Name,
				Policy:  &workerdv1.EgressPolicy{DefaultDeny: true},
			},
		}
	}

	gwName := computev1alpha1.DefaultEgressGatewayName
	if in.Egress != nil && in.Egress.GatewayRef != "" {
		gwName = string(in.Egress.GatewayRef)
	}

	gw, ok := gwByName[gwName]
	if !ok {
		if gwName == computev1alpha1.DefaultEgressGatewayName {
			// The implicit built-in allow-all gateway: no object required, no
			// policy on the wire (absent = allow-all, no enforcement).
			return ServiceEgressPlan{
				Name:    in.Name,
				Gateway: gwName,
				Ready:   true,
				Reason:  computev1alpha1.EgressReadyReasonApplied,
				Message: "using the implicit built-in allow-all default gateway",
				Config:  &workerdv1.ServiceEgressConfig{Service: in.Name},
			}
		}
		// A dangling explicit ref fails closed.
		return ServiceEgressPlan{
			Name:    in.Name,
			Gateway: gwName,
			Ready:   false,
			Reason:  computev1alpha1.EgressReadyReasonGatewayNotFound,
			Message: fmt.Sprintf("EgressGateway %q not found; egress fails closed", gwName),
			Config: &workerdv1.ServiceEgressConfig{
				Service: in.Name,
				Policy:  &workerdv1.EgressPolicy{DefaultDeny: true},
			},
		}
	}

	plan := ServiceEgressPlan{
		Name:    in.Name,
		Gateway: gwName,
		Ready:   true,
		Reason:  computev1alpha1.EgressReadyReasonApplied,
		Message: fmt.Sprintf("compiled from EgressGateway %q", gwName),
		Config: &workerdv1.ServiceEgressConfig{
			Service:  in.Name,
			Backends: backendsByGw[gwName],
			Policy: &workerdv1.EgressPolicy{
				DefaultDeny: gw.Spec.DefaultPolicy != computev1alpha1.EgressPolicyAllowAll,
				Rules:       rulesByGw[gwName],
			},
		},
	}
	if ready, _, msg := gatewayReadiness(gw); !ready {
		plan.Ready = false
		plan.Reason = computev1alpha1.EgressReadyReasonGatewayNotReady
		plan.Message = fmt.Sprintf("EgressGateway %q is not ready: %s", gwName, msg)
	}
	return plan
}

// listenerAddrs maps each of the gateway's status listeners to its dialable
// data-plane address (empty until the gateway data plane is provisioned).
func listenerAddrs(gw *computev1alpha1.EgressGateway) map[string]string {
	addrByName := make(map[string]string, len(gw.Status.Listeners))
	for _, ls := range gw.Status.Listeners {
		addrByName[ls.Name] = ls.BackendAddress
	}
	return addrByName
}

// compileBackends compiles a gateway's listeners into wire backends. Dialable
// addresses come from the gateway's listener status and are only exposed once
// the gateway is Ready (per the EgressGatewayConditionReady contract); until
// then the backend ships with an empty addr and the dialer skips it.
func compileBackends(gw *computev1alpha1.EgressGateway) []*workerdv1.BackendListener {
	ready := meta.IsStatusConditionTrue(gw.Status.Conditions, computev1alpha1.EgressGatewayConditionReady)
	addrByName := listenerAddrs(gw)

	backends := make([]*workerdv1.BackendListener, 0, len(gw.Spec.Listeners))
	for _, l := range gw.Spec.Listeners {
		shape, err := computev1alpha1.ShapeForListener(l)
		if err != nil {
			// Impossible past admission; skip defensively rather than compile
			// a meaningless backend.
			continue
		}
		var matchPort int32
		if l.Port != nil {
			matchPort = *l.Port
		}
		var addr string
		if ready {
			addr = addrByName[l.Name]
		}
		backends = append(backends, &workerdv1.BackendListener{
			Name:      l.Name,
			Addr:      addr,
			Shape:     string(shape),
			MatchPort: matchPort,
			Priority:  int32(computev1alpha1.ShapePriority(shape)),
		})
	}
	return backends
}

// compileRules flattens one accepted route attachment into wire rules: one
// rule per EgressRouteMatch (dimensions within a match are ANDed; matches and
// rules are ORed). listeners narrows the rule to the parentRef's sectionName;
// empty means all of the gateway's listeners.
func compileRules(route *computev1alpha1.EgressRoute, listeners []string) []*workerdv1.EgressRule {
	var rules []*workerdv1.EgressRule
	for _, rule := range route.Spec.Rules {
		for _, m := range rule.Matches {
			wire := &workerdv1.EgressRule{
				DestinationCidrs: m.DestinationCIDRs,
				Listeners:        listeners,
			}
			for _, h := range m.DestinationHostnames {
				wire.DestinationHostnames = append(wire.DestinationHostnames, string(h))
			}
			for _, p := range m.Ports {
				pr := &workerdv1.PortRange{}
				if p.Port != nil {
					pr.Start, pr.End = *p.Port, *p.Port
				} else if p.StartPort != nil && p.EndPort != nil {
					pr.Start, pr.End = *p.StartPort, *p.EndPort
				} else {
					continue
				}
				wire.Ports = append(wire.Ports, pr)
			}
			if m.Protocol != nil {
				wire.Protocol = string(*m.Protocol)
			}
			rules = append(rules, wire)
		}
	}
	return rules
}

// conditionStatus maps a boolean to a condition status.
func conditionStatus(ok bool) metav1.ConditionStatus {
	if ok {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

// gatewayReadiness derives the gateway Ready condition: every listener must
// have a dialable data-plane address.
func gatewayReadiness(gw *computev1alpha1.EgressGateway) (bool, string, string) {
	addrByName := listenerAddrs(gw)
	var pending []string
	for _, l := range gw.Spec.Listeners {
		if addrByName[l.Name] == "" {
			pending = append(pending, l.Name)
		}
	}
	if len(pending) > 0 {
		return false, computev1alpha1.EgressGatewayReasonListenersPending,
			fmt.Sprintf("listeners without a data plane address: %v", pending)
	}
	return true, computev1alpha1.EgressGatewayReasonReady, "all listeners have a dialable data plane"
}
