package v1alpha1

import (
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &EgressGateway{}

// Default fills the EgressGateway's documented defaults in Go (kubebuilder
// default markers don't fire on the aggregated apiserver — see
// defaultConfigSpec). The defaultPolicy pin matters: an explicitly created
// gateway must persist as deny-all so it fails closed. Deliberate asymmetry:
// the implicit built-in "default" gateway (no object) is allow-all so egress
// works out of the box — see DefaultEgressGatewayName.
//
// ServiceConfigSpec.Egress is intentionally NOT materialized by any
// defaulter: absent must stay absent (it means "the default gateway" at
// compile time, resolved by the control plane, not stored in the spec).
// EgressRoute has nothing to default.
func (g *EgressGateway) Default() {
	if g.Spec.DefaultPolicy == "" {
		g.Spec.DefaultPolicy = EgressPolicyDenyAll
	}
	for i := range g.Spec.Listeners {
		l := &g.Spec.Listeners[i]
		if l.Protocol == EgressProtocolTLS && l.TLS != nil && l.TLS.Mode == "" {
			l.TLS.Mode = EgressTLSPassthrough
		}
	}
}
