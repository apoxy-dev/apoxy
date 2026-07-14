package v1alpha1

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	runtime "k8s.io/apimachinery/pkg/runtime"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var (
	_ resourcestrategy.Validater       = &EgressGateway{}
	_ resourcestrategy.ValidateUpdater = &EgressGateway{}
	_ resourcestrategy.Validater       = &EgressRoute{}
	_ resourcestrategy.ValidateUpdater = &EgressRoute{}
)

// =============================================================================
// EgressGateway
// =============================================================================

func (g *EgressGateway) Validate(_ context.Context) field.ErrorList {
	return validateEgressGatewaySpec(&g.Spec, field.NewPath("spec"))
}

// ValidateUpdate re-runs full validation; the spec is mutable (routes and
// policy are meant to be tightened live).
func (g *EgressGateway) ValidateUpdate(ctx context.Context, _ runtime.Object) field.ErrorList {
	return g.Validate(ctx)
}

func validateEgressGatewaySpec(spec *EgressGatewaySpec, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	switch spec.DefaultPolicy {
	case "", EgressPolicyAllowAll, EgressPolicyDenyAll:
	default:
		errs = append(errs, field.NotSupported(p.Child("defaultPolicy"), spec.DefaultPolicy,
			[]string{string(EgressPolicyAllowAll), string(EgressPolicyDenyAll)}))
	}

	if len(spec.Listeners) == 0 {
		errs = append(errs, field.Required(p.Child("listeners"),
			"at least one listener is required"))
	}
	seen := map[string]struct{}{}
	for i := range spec.Listeners {
		lp := p.Child("listeners").Index(i)
		l := &spec.Listeners[i]

		if l.Name == "" {
			errs = append(errs, field.Required(lp.Child("name"), "listener name is required"))
		} else {
			for _, msg := range utilvalidation.IsDNS1123Label(l.Name) {
				errs = append(errs, field.Invalid(lp.Child("name"), l.Name, msg))
			}
			if _, dup := seen[l.Name]; dup {
				errs = append(errs, field.Duplicate(lp.Child("name"), l.Name))
			}
			seen[l.Name] = struct{}{}
		}

		switch l.Protocol {
		case EgressProtocolTCP, EgressProtocolHTTP, EgressProtocolHTTPS:
			if l.TLS != nil {
				errs = append(errs, field.Forbidden(lp.Child("tls"),
					"tls is only configurable on TLS listeners"))
			}
		case EgressProtocolTLS:
			errs = append(errs, validateListenerTLS(l.TLS, lp.Child("tls"))...)
		default:
			errs = append(errs, field.NotSupported(lp.Child("protocol"), l.Protocol,
				[]string{string(EgressProtocolTCP), string(EgressProtocolTLS),
					string(EgressProtocolHTTP), string(EgressProtocolHTTPS)}))
		}

		if l.Port != nil && (*l.Port < 1 || *l.Port > 65535) {
			errs = append(errs, field.Invalid(lp.Child("port"), *l.Port, "must be in [1,65535]"))
		}
	}
	return errs
}

// validateListenerTLS checks the TLS block of a TLS-protocol listener. A nil
// block is legal (defaulted to Passthrough).
func validateListenerTLS(tls *EgressListenerTLS, p *field.Path) field.ErrorList {
	if tls == nil {
		return nil
	}
	errs := field.ErrorList{}
	switch tls.Mode {
	case "", EgressTLSPassthrough:
		// Passthrough never terminates, so a CA would be dead config; reject
		// it so a Terminate typo doesn't silently ship an SNI-only listener.
		if tls.CACertRef != nil {
			errs = append(errs, field.Forbidden(p.Child("caCertRef"),
				"caCertRef is only used with mode=Terminate"))
		}
	case EgressTLSTerminate:
		if tls.CACertRef == nil {
			errs = append(errs, field.Required(p.Child("caCertRef"),
				"a CA cert is required to mint certificates when mode=Terminate"))
		} else {
			if tls.CACertRef.Store == "" {
				errs = append(errs, field.Required(p.Child("caCertRef", "store"),
					"store must name a SecretStore"))
			} else {
				for _, msg := range utilvalidation.IsDNS1123Subdomain(string(tls.CACertRef.Store)) {
					errs = append(errs, field.Invalid(p.Child("caCertRef", "store"), tls.CACertRef.Store, msg))
				}
			}
			if tls.CACertRef.Key == "" {
				errs = append(errs, field.Required(p.Child("caCertRef", "key"),
					"key within the store is required"))
			}
		}
	default:
		errs = append(errs, field.NotSupported(p.Child("mode"), tls.Mode,
			[]string{string(EgressTLSPassthrough), string(EgressTLSTerminate)}))
	}
	return errs
}

// =============================================================================
// EgressRoute
// =============================================================================

func (r *EgressRoute) Validate(_ context.Context) field.ErrorList {
	return validateEgressRouteSpec(&r.Spec, field.NewPath("spec"))
}

// ValidateUpdate re-runs full validation; the spec is mutable.
func (r *EgressRoute) ValidateUpdate(ctx context.Context, _ runtime.Object) field.ErrorList {
	return r.Validate(ctx)
}

func validateEgressRouteSpec(spec *EgressRouteSpec, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	if len(spec.ParentRefs) == 0 {
		errs = append(errs, field.Required(p.Child("parentRefs"),
			"at least one parentRef is required"))
	}
	for i := range spec.ParentRefs {
		errs = append(errs, validateEgressParentRef(&spec.ParentRefs[i],
			p.Child("parentRefs").Index(i))...)
	}

	if len(spec.Rules) == 0 {
		errs = append(errs, field.Required(p.Child("rules"), "at least one rule is required"))
	}
	for i := range spec.Rules {
		rp := p.Child("rules").Index(i)
		rule := &spec.Rules[i]
		if len(rule.Matches) == 0 {
			errs = append(errs, field.Required(rp.Child("matches"),
				"a rule must have at least one match (an empty rule matches nothing)"))
		}
		for j := range rule.Matches {
			errs = append(errs, validateEgressMatch(&rule.Matches[j],
				rp.Child("matches").Index(j))...)
		}
	}
	return errs
}

// validateEgressParentRef pins the parentRef to a compute EgressGateway:
// gateway-api's ParentReference is reused for its familiar shape, but the
// only legal parent kind here is compute.apoxy.dev/EgressGateway.
func validateEgressParentRef(ref *gwapiv1.ParentReference, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	if ref.Name == "" {
		errs = append(errs, field.Required(p.Child("name"), "parent gateway name is required"))
	}
	if ref.Group != nil && string(*ref.Group) != GroupName {
		errs = append(errs, field.NotSupported(p.Child("group"), string(*ref.Group),
			[]string{GroupName}))
	}
	if ref.Kind != nil && string(*ref.Kind) != "EgressGateway" {
		errs = append(errs, field.NotSupported(p.Child("kind"), string(*ref.Kind),
			[]string{"EgressGateway"}))
	}
	if ref.Namespace != nil {
		errs = append(errs, field.Forbidden(p.Child("namespace"),
			"must not be set; compute kinds are cluster-scoped"))
	}
	if ref.Port != nil {
		errs = append(errs, field.Forbidden(p.Child("port"),
			"attachment is by sectionName (listener name), not port"))
	}
	return errs
}

func validateEgressMatch(m *EgressRouteMatch, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	if len(m.DestinationCIDRs) == 0 && len(m.DestinationHostnames) == 0 &&
		len(m.Ports) == 0 && m.Protocol == nil {
		errs = append(errs, field.Required(p,
			"a match must set at least one of destinationCIDRs, destinationHostnames, ports, protocol"))
	}

	for i, c := range m.DestinationCIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			errs = append(errs, field.Invalid(p.Child("destinationCIDRs").Index(i), c,
				"must be a CIDR (single IPs as /32 or /128)"))
			continue
		}
		// Host bits are rejected rather than silently masked: the spec string
		// is what users and every future consumer see, so it must be
		// unambiguous (10.0.0.1/24 vs 10.0.0.0/24).
		if pfx.Masked() != pfx {
			errs = append(errs, field.Invalid(p.Child("destinationCIDRs").Index(i), c,
				fmt.Sprintf("must not have host bits set (did you mean %s?)", pfx.Masked())))
		}
	}

	for i, h := range m.DestinationHostnames {
		errs = append(errs, validateEgressHostname(string(h),
			p.Child("destinationHostnames").Index(i))...)
	}

	for i := range m.Ports {
		errs = append(errs, validateEgressPortMatch(&m.Ports[i], p.Child("ports").Index(i))...)
	}

	// UDP is in the enum for forward compatibility but the netstack is
	// fail-closed on UDP, so only TCP is admitted today.
	if m.Protocol != nil && *m.Protocol != EgressRouteProtocolTCP {
		errs = append(errs, field.NotSupported(p.Child("protocol"), *m.Protocol,
			[]string{string(EgressRouteProtocolTCP)}))
	}
	return errs
}

// validateEgressHostname accepts exact hostnames and single-label wildcards
// (gwapiv1.Hostname semantics: `*.example.com` matches exactly one prefix
// label; a bare `*` is not a hostname, and IPs are not hostnames — an IP
// literal can never appear as SNI (RFC 6066), so admitting one would store a
// rule that silently matches nothing; use destinationCIDRs for IPs).
func validateEgressHostname(h string, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	base := h
	if strings.HasPrefix(h, "*.") {
		base = h[2:]
	}
	if base == "" || strings.Contains(base, "*") {
		errs = append(errs, field.Invalid(p, h,
			"must be an exact hostname or a single leading wildcard label (*.example.com)"))
		return errs
	}
	if _, err := netip.ParseAddr(base); err == nil {
		errs = append(errs, field.Invalid(p, h,
			"must be a hostname, not an IP address; use destinationCIDRs to match IPs"))
		return errs
	}
	for _, msg := range utilvalidation.IsDNS1123Subdomain(base) {
		errs = append(errs, field.Invalid(p, h, msg))
	}
	return errs
}

func validateEgressPortMatch(pm *EgressPortMatch, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	inRange := func(v int32) bool { return v >= 1 && v <= 65535 }

	switch {
	case pm.Port != nil:
		if pm.StartPort != nil || pm.EndPort != nil {
			errs = append(errs, field.Forbidden(p,
				"port and startPort/endPort are mutually exclusive"))
		}
		if !inRange(*pm.Port) {
			errs = append(errs, field.Invalid(p.Child("port"), *pm.Port, "must be in [1,65535]"))
		}
	case pm.StartPort != nil || pm.EndPort != nil:
		if pm.StartPort == nil || pm.EndPort == nil {
			errs = append(errs, field.Required(p,
				"startPort and endPort must be set together"))
			break
		}
		if !inRange(*pm.StartPort) {
			errs = append(errs, field.Invalid(p.Child("startPort"), *pm.StartPort, "must be in [1,65535]"))
		}
		if !inRange(*pm.EndPort) {
			errs = append(errs, field.Invalid(p.Child("endPort"), *pm.EndPort, "must be in [1,65535]"))
		}
		if inRange(*pm.StartPort) && inRange(*pm.EndPort) && *pm.StartPort > *pm.EndPort {
			errs = append(errs, field.Invalid(p.Child("endPort"), *pm.EndPort,
				"endPort must be >= startPort"))
		}
	default:
		errs = append(errs, field.Required(p, "either port or startPort+endPort must be set"))
	}
	return errs
}
