package gatewayapi

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

// TestGRPCRouteExtensionRefFilter pins that a GRPCRoute ExtensionRef filter
// goes through the same extension kinds as an HTTPRoute one, so a
// DirectResponse on a GRPCRoute reaches the IR instead of failing validation.
func TestGRPCRouteExtensionRefFilter(t *testing.T) {
	const controller = "apoxy.dev/gatewayclass-cloud"
	directResponse := schema.GroupKind{Group: extensionsv1alpha2.GroupVersion.Group, Kind: "DirectResponse"}

	cases := []struct {
		name       string
		extKinds   []schema.GroupKind
		wantRoutes int
		wantStatus uint32
		wantReason gwapiv1.RouteConditionReason
	}{
		{name: "direct response is an extension kind", extKinds: []schema.GroupKind{directResponse}, wantRoutes: 1, wantStatus: 418, wantReason: gwapiv1.RouteReasonAccepted},
		{name: "unknown extension kind is rejected", wantRoutes: 0, wantReason: gwapiv1.RouteReasonUnsupportedValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gc := &gwapiv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "apoxy"}, Spec: gwapiv1.GatewayClassSpec{ControllerName: controller}}
			gw := &gwapiv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: gwapiv1.GatewaySpec{
				GatewayClassName: "apoxy",
				Listeners:        []gwapiv1.Listener{{Name: "http", Protocol: gwapiv1.HTTPProtocolType, Port: 80}},
			}}
			dr := &extensionsv1alpha2.DirectResponse{ObjectMeta: metav1.ObjectMeta{Name: "dr", Namespace: "proj"}, Spec: extensionsv1alpha2.DirectResponseSpec{StatusCode: ptr.To(int32(418))}}
			gr := &gwapiv1a2.GRPCRoute{
				TypeMeta:   metav1.TypeMeta{Kind: KindGRPCRoute},
				ObjectMeta: metav1.ObjectMeta{Name: "echo", Namespace: "proj"},
				Spec: gwapiv1.GRPCRouteSpec{
					CommonRouteSpec: gwapiv1.CommonRouteSpec{ParentRefs: []gwapiv1.ParentReference{{Kind: ptr.To(gwapiv1.Kind("Gateway")), Name: "default", Port: ptr.To(gwapiv1.PortNumber(80))}}},
					Hostnames:       []gwapiv1.Hostname{"echo.example.com"},
					Rules: []gwapiv1.GRPCRouteRule{{
						Matches: []gwapiv1.GRPCRouteMatch{{Method: &gwapiv1.GRPCMethodMatch{Type: ptr.To(gwapiv1.GRPCMethodMatchExact), Service: ptr.To("it.Echo"), Method: ptr.To("Ping")}}},
						Filters: []gwapiv1.GRPCRouteFilter{{Type: gwapiv1.GRPCRouteFilterExtensionRef, ExtensionRef: &gwapiv1.LocalObjectReference{Group: gwapiv1.Group(directResponse.Group), Kind: gwapiv1.Kind(directResponse.Kind), Name: "dr"}}},
					}},
				},
			}
			tr := &Translator{GatewayControllerName: controller, GatewayClassName: "apoxy", ExtensionGroupKinds: tc.extKinds}
			out := tr.Translate(&Resources{
				GatewayClass:    gc,
				Gateways:        []*gwapiv1.Gateway{gw},
				GRPCRoutes:      []*gwapiv1a2.GRPCRoute{gr},
				DirectResponses: []*extensionsv1alpha2.DirectResponse{dr},
			})

			if len(out.GRPCRoutes) != 1 || len(out.GRPCRoutes[0].Status.Parents) != 1 {
				t.Fatalf("want one GRPCRoute with one parent status, got %+v", out.GRPCRoutes)
			}
			var accepted *metav1.Condition
			for i, c := range out.GRPCRoutes[0].Status.Parents[0].Conditions {
				if c.Type == string(gwapiv1.RouteConditionAccepted) {
					accepted = &out.GRPCRoutes[0].Status.Parents[0].Conditions[i]
				}
			}
			if accepted == nil || accepted.Reason != string(tc.wantReason) {
				t.Fatalf("Accepted condition = %+v, want reason %s", accepted, tc.wantReason)
			}

			var routes int
			for _, x := range out.XdsIR {
				for _, l := range x.HTTP {
					for _, r := range l.Routes {
						routes++
						if r.PathMatch == nil || r.PathMatch.Exact == nil || *r.PathMatch.Exact != "/it.Echo/Ping" {
							t.Errorf("route %s path match = %+v, want exact /it.Echo/Ping", r.Name, r.PathMatch)
						}
						if r.DirectResponse == nil || r.DirectResponse.StatusCode != tc.wantStatus {
							t.Errorf("route %s direct response = %+v, want status %d", r.Name, r.DirectResponse, tc.wantStatus)
						}
					}
				}
			}
			if routes != tc.wantRoutes {
				t.Fatalf("IR routes = %d, want %d", routes, tc.wantRoutes)
			}
		})
	}
}
