package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// validEgressGateway returns a gateway that passes Validate: one HTTPS
// listener plus one TLS-terminate listener with a CA ref.
func validEgressGateway() *EgressGateway {
	return &EgressGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "eg"},
		Spec: EgressGatewaySpec{
			DefaultPolicy: EgressPolicyDenyAll,
			Listeners: []EgressListener{
				{Name: "https", Protocol: EgressProtocolHTTPS, Port: ptr.To(int32(443))},
				{Name: "mitm", Protocol: EgressProtocolTLS, TLS: &EgressListenerTLS{
					Mode:      EgressTLSTerminate,
					CACertRef: &SecretKeyRef{Store: "egress-ca", Key: "ca.pem"},
				}},
			},
		},
	}
}

func TestEgressGatewayValidate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(g *EgressGateway)
		want   []string
	}{
		{
			name:   "valid gateway accepted",
			mutate: func(g *EgressGateway) {},
		},
		{
			name:   "empty defaultPolicy accepted (pre-default)",
			mutate: func(g *EgressGateway) { g.Spec.DefaultPolicy = "" },
		},
		{
			name:   "unknown defaultPolicy rejected",
			mutate: func(g *EgressGateway) { g.Spec.DefaultPolicy = "open-bar" },
			want:   []string{"spec.defaultPolicy"},
		},
		{
			name:   "no listeners rejected",
			mutate: func(g *EgressGateway) { g.Spec.Listeners = nil },
			want:   []string{"spec.listeners"},
		},
		{
			name: "empty listener name rejected",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[0].Name = ""
			},
			want: []string{"spec.listeners[0].name"},
		},
		{
			name: "duplicate listener names rejected",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[1] = EgressListener{Name: "https", Protocol: EgressProtocolHTTP}
			},
			want: []string{"spec.listeners[1].name"},
		},
		{
			name: "non-label listener name rejected",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[0].Name = "Not_A_Label"
			},
			want: []string{"spec.listeners[0].name"},
		},
		{
			name: "UDP protocol rejected",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[0].Protocol = "UDP"
			},
			want: []string{"spec.listeners[0].protocol"},
		},
		{
			name: "tls block on a non-TLS listener rejected",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[0].TLS = &EgressListenerTLS{Mode: EgressTLSPassthrough}
			},
			want: []string{"spec.listeners[0].tls"},
		},
		{
			name: "terminate without caCertRef rejected",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[1].TLS.CACertRef = nil
			},
			want: []string{"spec.listeners[1].tls.caCertRef"},
		},
		{
			name: "terminate with empty store/key rejected",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[1].TLS.CACertRef = &SecretKeyRef{}
			},
			want: []string{"spec.listeners[1].tls.caCertRef.store", "spec.listeners[1].tls.caCertRef.key"},
		},
		{
			name: "passthrough with caCertRef rejected (dead config)",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[1].TLS.Mode = EgressTLSPassthrough
			},
			want: []string{"spec.listeners[1].tls.caCertRef"},
		},
		{
			name: "TLS listener with nil tls block accepted (defaults to passthrough)",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[1].TLS = nil
			},
		},
		{
			name: "out-of-range port rejected",
			mutate: func(g *EgressGateway) {
				g.Spec.Listeners[0].Port = ptr.To(int32(0))
			},
			want: []string{"spec.listeners[0].port"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := validEgressGateway()
			tc.mutate(g)
			assertErrs(t, g.Validate(context.Background()), tc.want, 0)
			// The spec is mutable: updates re-run the same validation.
			assertErrs(t, g.ValidateUpdate(context.Background(), validEgressGateway()), tc.want, 0)
		})
	}
}

// validEgressRoute returns a route that passes Validate: attached to one
// gateway listener, allowing one hostname on 443.
func validEgressRoute() *EgressRoute {
	return &EgressRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-openai"},
		Spec: EgressRouteSpec{
			ParentRefs: []gwapiv1.ParentReference{{
				Name:        "eg",
				SectionName: ptr.To(gwapiv1.SectionName("https")),
			}},
			Rules: []EgressRouteRule{{
				Matches: []EgressRouteMatch{{
					DestinationHostnames: []gwapiv1.Hostname{"api.openai.com"},
					Ports:                []EgressPortMatch{{Port: ptr.To(int32(443))}},
				}},
			}},
		},
	}
}

func TestEgressRouteValidate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *EgressRoute)
		want   []string
	}{
		{
			name:   "valid route accepted",
			mutate: func(r *EgressRoute) {},
		},
		{
			name:   "no parentRefs rejected",
			mutate: func(r *EgressRoute) { r.Spec.ParentRefs = nil },
			want:   []string{"spec.parentRefs"},
		},
		{
			name: "parentRef without name rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.ParentRefs[0].Name = ""
			},
			want: []string{"spec.parentRefs[0].name"},
		},
		{
			name: "foreign group rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.ParentRefs[0].Group = ptr.To(gwapiv1.Group("gateway.networking.k8s.io"))
			},
			want: []string{"spec.parentRefs[0].group"},
		},
		{
			name: "matching group and kind accepted",
			mutate: func(r *EgressRoute) {
				r.Spec.ParentRefs[0].Group = ptr.To(gwapiv1.Group(GroupName))
				r.Spec.ParentRefs[0].Kind = ptr.To(gwapiv1.Kind("EgressGateway"))
			},
		},
		{
			name: "foreign kind rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.ParentRefs[0].Kind = ptr.To(gwapiv1.Kind("Gateway"))
			},
			want: []string{"spec.parentRefs[0].kind"},
		},
		{
			name: "namespace rejected (cluster-scoped)",
			mutate: func(r *EgressRoute) {
				r.Spec.ParentRefs[0].Namespace = ptr.To(gwapiv1.Namespace("default"))
			},
			want: []string{"spec.parentRefs[0].namespace"},
		},
		{
			name: "parentRef port rejected (attachment is by sectionName)",
			mutate: func(r *EgressRoute) {
				r.Spec.ParentRefs[0].Port = ptr.To(gwapiv1.PortNumber(443))
			},
			want: []string{"spec.parentRefs[0].port"},
		},
		{
			name:   "no rules rejected",
			mutate: func(r *EgressRoute) { r.Spec.Rules = nil },
			want:   []string{"spec.rules"},
		},
		{
			name: "rule without matches rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches = nil
			},
			want: []string{"spec.rules[0].matches"},
		},
		{
			name: "empty match rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0] = EgressRouteMatch{}
			},
			want: []string{"spec.rules[0].matches[0]"},
		},
		{
			name: "bare IP is not a CIDR",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].DestinationCIDRs = []string{"10.0.0.1"}
			},
			want: []string{"spec.rules[0].matches[0].destinationCIDRs[0]"},
		},
		{
			name: "v4 and v6 CIDRs accepted",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].DestinationCIDRs = []string{"10.0.0.1/32", "2001:db8::/64"}
			},
		},
		{
			name: "CIDR with host bits rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].DestinationCIDRs = []string{"10.0.0.1/24", "2001:db8::1/64"}
			},
			want: []string{
				"spec.rules[0].matches[0].destinationCIDRs[0]",
				"spec.rules[0].matches[0].destinationCIDRs[1]",
			},
		},
		{
			name: "wildcard hostname accepted",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].DestinationHostnames = []gwapiv1.Hostname{"*.openai.com"}
			},
		},
		{
			name: "bare star hostname rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].DestinationHostnames = []gwapiv1.Hostname{"*"}
			},
			want: []string{"spec.rules[0].matches[0].destinationHostnames[0]"},
		},
		{
			name: "inner wildcard rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].DestinationHostnames = []gwapiv1.Hostname{"api.*.com"}
			},
			want: []string{"spec.rules[0].matches[0].destinationHostnames[0]"},
		},
		{
			name: "IP literal hostname rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].DestinationHostnames = []gwapiv1.Hostname{"10.0.0.1"}
			},
			want: []string{"spec.rules[0].matches[0].destinationHostnames[0]"},
		},
		{
			name: "wildcard over IP literal rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].DestinationHostnames = []gwapiv1.Hostname{"*.10.0.0.1"}
			},
			want: []string{"spec.rules[0].matches[0].destinationHostnames[0]"},
		},
		{
			name: "port range accepted",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].Ports = []EgressPortMatch{{
					StartPort: ptr.To(int32(8000)), EndPort: ptr.To(int32(9000)),
				}}
			},
		},
		{
			name: "port and range together rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].Ports = []EgressPortMatch{{
					Port: ptr.To(int32(443)), StartPort: ptr.To(int32(1)), EndPort: ptr.To(int32(2)),
				}}
			},
			want: []string{"spec.rules[0].matches[0].ports[0]"},
		},
		{
			name: "half-open range rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].Ports = []EgressPortMatch{{
					StartPort: ptr.To(int32(8000)),
				}}
			},
			want: []string{"spec.rules[0].matches[0].ports[0]"},
		},
		{
			name: "inverted range rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].Ports = []EgressPortMatch{{
					StartPort: ptr.To(int32(9000)), EndPort: ptr.To(int32(8000)),
				}}
			},
			want: []string{"spec.rules[0].matches[0].ports[0].endPort"},
		},
		{
			name: "empty port match rejected",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].Ports = []EgressPortMatch{{}}
			},
			want: []string{"spec.rules[0].matches[0].ports[0]"},
		},
		{
			name: "TCP protocol accepted",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].Protocol = ptr.To(EgressRouteProtocolTCP)
			},
		},
		{
			name: "UDP protocol rejected (not yet supported)",
			mutate: func(r *EgressRoute) {
				r.Spec.Rules[0].Matches[0].Protocol = ptr.To(EgressRouteProtocolUDP)
			},
			want: []string{"spec.rules[0].matches[0].protocol"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validEgressRoute()
			tc.mutate(r)
			assertErrs(t, r.Validate(context.Background()), tc.want, 0)
			assertErrs(t, r.ValidateUpdate(context.Background(), validEgressRoute()), tc.want, 0)
		})
	}
}

func TestEgressGatewayDefault(t *testing.T) {
	cases := []struct {
		name   string
		in     *EgressGateway
		verify func(t *testing.T, g *EgressGateway)
	}{
		{
			name: "empty defaultPolicy pins deny-all (explicit gateways fail closed)",
			in:   &EgressGateway{Spec: EgressGatewaySpec{Listeners: []EgressListener{{Name: "l", Protocol: EgressProtocolHTTP}}}},
			verify: func(t *testing.T, g *EgressGateway) {
				if g.Spec.DefaultPolicy != EgressPolicyDenyAll {
					t.Errorf("DefaultPolicy = %q; want deny-all", g.Spec.DefaultPolicy)
				}
			},
		},
		{
			name: "explicit allow-all preserved",
			in:   &EgressGateway{Spec: EgressGatewaySpec{DefaultPolicy: EgressPolicyAllowAll}},
			verify: func(t *testing.T, g *EgressGateway) {
				if g.Spec.DefaultPolicy != EgressPolicyAllowAll {
					t.Errorf("DefaultPolicy = %q; want allow-all", g.Spec.DefaultPolicy)
				}
			},
		},
		{
			name: "TLS listener with empty mode defaults to Passthrough",
			in: &EgressGateway{Spec: EgressGatewaySpec{Listeners: []EgressListener{
				{Name: "tls", Protocol: EgressProtocolTLS, TLS: &EgressListenerTLS{}},
				{Name: "tcp", Protocol: EgressProtocolTCP},
			}}},
			verify: func(t *testing.T, g *EgressGateway) {
				if g.Spec.Listeners[0].TLS.Mode != EgressTLSPassthrough {
					t.Errorf("TLS.Mode = %q; want Passthrough", g.Spec.Listeners[0].TLS.Mode)
				}
				if g.Spec.Listeners[1].TLS != nil {
					t.Errorf("non-TLS listener grew a TLS block: %+v", g.Spec.Listeners[1].TLS)
				}
			},
		},
		{
			name: "TLS listener with nil tls block stays nil (passthrough is implicit)",
			in: &EgressGateway{Spec: EgressGatewaySpec{Listeners: []EgressListener{
				{Name: "tls", Protocol: EgressProtocolTLS},
			}}},
			verify: func(t *testing.T, g *EgressGateway) {
				if g.Spec.Listeners[0].TLS != nil {
					t.Errorf("nil TLS block was materialized: %+v", g.Spec.Listeners[0].TLS)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.Default()
			tc.verify(t, tc.in)
		})
	}
}

func TestEgressShapeForListener(t *testing.T) {
	cases := []struct {
		name     string
		listener EgressListener
		want     EgressListenerShape
		wantErr  bool
	}{
		{name: "http", listener: EgressListener{Protocol: EgressProtocolHTTP}, want: EgressShapeHTTP},
		{name: "https", listener: EgressListener{Protocol: EgressProtocolHTTPS}, want: EgressShapeHTTPS},
		{name: "tcp", listener: EgressListener{Protocol: EgressProtocolTCP}, want: EgressShapeTCP},
		{name: "tls nil block defaults passthrough", listener: EgressListener{Protocol: EgressProtocolTLS}, want: EgressShapeTLSPassthrough},
		{name: "tls terminate", listener: EgressListener{Protocol: EgressProtocolTLS, TLS: &EgressListenerTLS{Mode: EgressTLSTerminate}}, want: EgressShapeTLSTerminate},
		{name: "unknown protocol errors", listener: EgressListener{Protocol: "UDP"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ShapeForListener(tc.listener)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ShapeForListener = %q; want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ShapeForListener: %v", err)
			}
			if got != tc.want {
				t.Errorf("ShapeForListener = %q; want %q", got, tc.want)
			}
		})
	}

	// Priority must strictly order the shapes so dial-time tiebreaks are
	// deterministic: sniffing shapes outrank hard-committing ones.
	order := []EgressListenerShape{EgressShapeTLSTerminate, EgressShapeHTTPS,
		EgressShapeHTTP, EgressShapeTLSPassthrough, EgressShapeTCP}
	for i := 1; i < len(order); i++ {
		if ShapePriority(order[i-1]) <= ShapePriority(order[i]) {
			t.Errorf("ShapePriority(%s)=%d not > ShapePriority(%s)=%d",
				order[i-1], ShapePriority(order[i-1]), order[i], ShapePriority(order[i]))
		}
	}
}
