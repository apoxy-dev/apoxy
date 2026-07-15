// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	workerdv1 "github.com/apoxy-dev/apoxy/api/workerd/v1"
)

// egw builds an EgressGateway fixture.
func egw(name string, policy computev1alpha1.EgressDefaultPolicy, listeners ...computev1alpha1.EgressListener) computev1alpha1.EgressGateway {
	return computev1alpha1.EgressGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: computev1alpha1.EgressGatewaySpec{
			DefaultPolicy: policy,
			Listeners:     listeners,
		},
	}
}

// readyGw marks a gateway Ready with data-plane addresses for every listener.
func readyGw(gw computev1alpha1.EgressGateway, addr string) computev1alpha1.EgressGateway {
	for _, l := range gw.Spec.Listeners {
		gw.Status.Listeners = append(gw.Status.Listeners, computev1alpha1.EgressListenerStatus{
			Name: l.Name, BackendAddress: addr,
		})
	}
	gw.Status.Conditions = []metav1.Condition{{
		Type:   computev1alpha1.EgressGatewayConditionReady,
		Status: metav1.ConditionTrue,
		Reason: computev1alpha1.EgressGatewayReasonReady,
	}}
	return gw
}

// eroute builds an EgressRoute fixture attached to gateway (optionally one
// listener via sectionName).
func eroute(name, gateway, sectionName string, matches ...computev1alpha1.EgressRouteMatch) computev1alpha1.EgressRoute {
	ref := gwapiv1.ParentReference{Name: gwapiv1.ObjectName(gateway)}
	if sectionName != "" {
		ref.SectionName = ptr.To(gwapiv1.SectionName(sectionName))
	}
	return computev1alpha1.EgressRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: computev1alpha1.EgressRouteSpec{
			ParentRefs: []gwapiv1.ParentReference{ref},
			Rules:      []computev1alpha1.EgressRouteRule{{Matches: matches}},
		},
	}
}

func serviceByName(t *testing.T, plan *EgressPlan, name string) ServiceEgressPlan {
	t.Helper()
	for _, s := range plan.Services {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("service %q missing from plan (%+v)", name, plan.Services)
	return ServiceEgressPlan{}
}

func TestCompileEgress_ServiceResolution(t *testing.T) {
	httpsListener := computev1alpha1.EgressListener{Name: "https", Protocol: computev1alpha1.EgressProtocolHTTPS}

	cases := []struct {
		name     string
		egress   *computev1alpha1.ServiceEgress
		gateways []computev1alpha1.EgressGateway

		wantReady   bool
		wantReason  string
		wantGateway string
		// wantPolicy nil means no policy on the wire (allow-all).
		wantPolicy   *workerdv1.EgressPolicy
		wantBackends int
	}{
		{
			name:       "no egress block resolves to the implicit built-in default",
			egress:     nil,
			wantReady:  true,
			wantReason: computev1alpha1.EgressReadyReasonApplied, wantGateway: "default",
			wantPolicy: nil,
		},
		{
			name:       "empty egress block resolves to the implicit built-in default",
			egress:     &computev1alpha1.ServiceEgress{},
			wantReady:  true,
			wantReason: computev1alpha1.EgressReadyReasonApplied, wantGateway: "default",
			wantPolicy: nil,
		},
		{
			name:       "disabled hard-denies",
			egress:     &computev1alpha1.ServiceEgress{Disabled: true},
			wantReady:  true,
			wantReason: computev1alpha1.EgressReadyReasonDisabled, wantGateway: "",
			wantPolicy: &workerdv1.EgressPolicy{DefaultDeny: true},
		},
		{
			name:       "dangling explicit ref fails closed",
			egress:     &computev1alpha1.ServiceEgress{GatewayRef: "missing"},
			wantReady:  false,
			wantReason: computev1alpha1.EgressReadyReasonGatewayNotFound, wantGateway: "missing",
			wantPolicy: &workerdv1.EgressPolicy{DefaultDeny: true},
		},
		{
			name:   "created default gateway overrides the built-in",
			egress: nil,
			gateways: []computev1alpha1.EgressGateway{
				readyGw(egw("default", computev1alpha1.EgressPolicyDenyAll, httpsListener), "10.0.0.1:8093"),
			},
			wantReady:  true,
			wantReason: computev1alpha1.EgressReadyReasonApplied, wantGateway: "default",
			wantPolicy:   &workerdv1.EgressPolicy{DefaultDeny: true},
			wantBackends: 1,
		},
		{
			name:   "explicit ref to a not-ready gateway compiles but reports GatewayNotReady",
			egress: &computev1alpha1.ServiceEgress{GatewayRef: "locked-down"},
			gateways: []computev1alpha1.EgressGateway{
				egw("locked-down", computev1alpha1.EgressPolicyDenyAll, httpsListener),
			},
			wantReady:  false,
			wantReason: computev1alpha1.EgressReadyReasonGatewayNotReady, wantGateway: "locked-down",
			wantPolicy:   &workerdv1.EgressPolicy{DefaultDeny: true},
			wantBackends: 1,
		},
		{
			name:   "allow-all gateway compiles default_deny=false",
			egress: &computev1alpha1.ServiceEgress{GatewayRef: "open"},
			gateways: []computev1alpha1.EgressGateway{
				readyGw(egw("open", computev1alpha1.EgressPolicyAllowAll, httpsListener), "10.0.0.1:8093"),
			},
			wantReady:  true,
			wantReason: computev1alpha1.EgressReadyReasonApplied, wantGateway: "open",
			wantPolicy:   &workerdv1.EgressPolicy{DefaultDeny: false},
			wantBackends: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := CompileEgress(
				[]ServiceEgressInput{{Name: "api", Egress: tc.egress}},
				tc.gateways, nil)
			sp := serviceByName(t, plan, "api")
			if sp.Ready != tc.wantReady || sp.Reason != tc.wantReason {
				t.Errorf("condition = ready=%v reason=%q (%s); want ready=%v reason=%q",
					sp.Ready, sp.Reason, sp.Message, tc.wantReady, tc.wantReason)
			}
			if sp.Gateway != tc.wantGateway {
				t.Errorf("gateway = %q; want %q", sp.Gateway, tc.wantGateway)
			}
			if sp.Config.Service != "api" {
				t.Errorf("wire service = %q; want %q", sp.Config.Service, "api")
			}
			if (sp.Config.Policy == nil) != (tc.wantPolicy == nil) {
				t.Fatalf("wire policy = %+v; want %+v", sp.Config.Policy, tc.wantPolicy)
			}
			if tc.wantPolicy != nil && sp.Config.Policy.DefaultDeny != tc.wantPolicy.DefaultDeny {
				t.Errorf("wire default_deny = %v; want %v", sp.Config.Policy.DefaultDeny, tc.wantPolicy.DefaultDeny)
			}
			if len(sp.Config.Backends) != tc.wantBackends {
				t.Errorf("wire backends = %+v; want %d", sp.Config.Backends, tc.wantBackends)
			}
		})
	}
}

func TestCompileEgress_Backends(t *testing.T) {
	gw := egw("eg", computev1alpha1.EgressPolicyDenyAll,
		computev1alpha1.EgressListener{Name: "https", Protocol: computev1alpha1.EgressProtocolHTTPS, Port: ptr.To(int32(443))},
		computev1alpha1.EgressListener{Name: "mitm", Protocol: computev1alpha1.EgressProtocolTLS,
			TLS: &computev1alpha1.EgressListenerTLS{Mode: computev1alpha1.EgressTLSTerminate}},
		computev1alpha1.EgressListener{Name: "raw", Protocol: computev1alpha1.EgressProtocolTCP},
	)
	in := []ServiceEgressInput{{Name: "api", Egress: &computev1alpha1.ServiceEgress{GatewayRef: "eg"}}}

	t.Run("shapes, ports, and priorities compile; not-ready gateway ships no addrs", func(t *testing.T) {
		plan := CompileEgress(in, []computev1alpha1.EgressGateway{gw}, nil)
		got := serviceByName(t, plan, "api").Config.Backends
		want := []*workerdv1.BackendListener{
			{Name: "https", Shape: "https", MatchPort: 443, Priority: 4},
			{Name: "mitm", Shape: "tls-terminate", Priority: 5},
			{Name: "raw", Shape: "tcp", Priority: 1},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("backends = %+v; want %+v", got, want)
		}
	})

	t.Run("ready gateway exposes data-plane addrs", func(t *testing.T) {
		plan := CompileEgress(in, []computev1alpha1.EgressGateway{readyGw(gw, "10.0.0.1:8093")}, nil)
		for _, b := range serviceByName(t, plan, "api").Config.Backends {
			if b.Addr != "10.0.0.1:8093" {
				t.Errorf("backend %s addr = %q; want the data-plane address", b.Name, b.Addr)
			}
		}
	})
}

func TestCompileEgress_Routes(t *testing.T) {
	gw := egw("eg", computev1alpha1.EgressPolicyDenyAll,
		computev1alpha1.EgressListener{Name: "https", Protocol: computev1alpha1.EgressProtocolHTTPS},
		computev1alpha1.EgressListener{Name: "raw", Protocol: computev1alpha1.EgressProtocolTCP},
	)
	openai := computev1alpha1.EgressRouteMatch{
		DestinationHostnames: []gwapiv1.Hostname{"api.openai.com", "*.openai.com"},
		Ports:                []computev1alpha1.EgressPortMatch{{Port: ptr.To(int32(443))}},
		Protocol:             ptr.To(computev1alpha1.EgressRouteProtocolTCP),
	}
	cidr := computev1alpha1.EgressRouteMatch{
		DestinationCIDRs: []string{"192.0.2.0/24"},
		Ports:            []computev1alpha1.EgressPortMatch{{StartPort: ptr.To(int32(8000)), EndPort: ptr.To(int32(8100))}},
	}
	in := []ServiceEgressInput{{Name: "api", Egress: &computev1alpha1.ServiceEgress{GatewayRef: "eg"}}}

	t.Run("matches compile to ORed wire rules with sectionName listener binding", func(t *testing.T) {
		routes := []computev1alpha1.EgressRoute{eroute("allow-openai", "eg", "https", openai, cidr)}
		plan := CompileEgress(in, []computev1alpha1.EgressGateway{gw}, routes)

		rules := serviceByName(t, plan, "api").Config.Policy.Rules
		want := []*workerdv1.EgressRule{
			{
				DestinationHostnames: []string{"api.openai.com", "*.openai.com"},
				Ports:                []*workerdv1.PortRange{{Start: 443, End: 443}},
				Protocol:             "TCP",
				Listeners:            []string{"https"},
			},
			{
				DestinationCidrs: []string{"192.0.2.0/24"},
				Ports:            []*workerdv1.PortRange{{Start: 8000, End: 8100}},
				Listeners:        []string{"https"},
			},
		}
		if !reflect.DeepEqual(rules, want) {
			t.Errorf("rules = %+v; want %+v", rules, want)
		}
	})

	t.Run("attachment counts and parents", func(t *testing.T) {
		routes := []computev1alpha1.EgressRoute{
			eroute("sectioned", "eg", "https", openai),
			eroute("all-listeners", "eg", "", cidr),
			eroute("bad-section", "eg", "nope", openai),
			eroute("bad-gateway", "missing", "", openai),
		}
		plan := CompileEgress(in, []computev1alpha1.EgressGateway{gw}, routes)

		if len(plan.Gateways) != 1 {
			t.Fatalf("gateways = %+v; want 1", plan.Gateways)
		}
		attached := plan.Gateways[0].AttachedRoutes
		if attached["https"] != 2 || attached["raw"] != 1 {
			t.Errorf("attachedRoutes = %+v; want https=2 raw=1", attached)
		}

		wantAccepted := map[string]bool{
			"sectioned": true, "all-listeners": true, "bad-section": false, "bad-gateway": false,
		}
		for _, rp := range plan.Routes {
			if len(rp.Parents) != 1 || len(rp.Parents[0].Conditions) != 1 {
				t.Fatalf("route %s parents = %+v; want one parent with one condition", rp.Name, rp.Parents)
			}
			cond := rp.Parents[0].Conditions[0]
			if got := cond.Status == metav1.ConditionTrue; got != wantAccepted[rp.Name] {
				t.Errorf("route %s accepted = %v (%s); want %v", rp.Name, got, cond.Message, wantAccepted[rp.Name])
			}
			if rp.Parents[0].ControllerName != computev1alpha1.EgressControllerName {
				t.Errorf("route %s controllerName = %q", rp.Name, rp.Parents[0].ControllerName)
			}
		}

		// Only accepted attachments contribute rules: sectioned (1 match) +
		// all-listeners (1 match); the rejected ones add nothing.
		rules := serviceByName(t, plan, "api").Config.Policy.Rules
		if len(rules) != 2 {
			t.Errorf("rules = %+v; want 2 (one per accepted attachment's match)", rules)
		}
	})
}

func TestCompileEgress_Deterministic(t *testing.T) {
	in := []ServiceEgressInput{
		{Name: "zeta"}, {Name: "alpha"}, {Name: "mid"},
	}
	plan := CompileEgress(in, nil, nil)
	var names []string
	for _, s := range plan.Services {
		names = append(names, s.Name)
	}
	want := []string{"alpha", "mid", "zeta"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("service order = %v; want %v", names, want)
	}
}
