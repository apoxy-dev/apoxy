package v1alpha1

import (
	"context"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &VPCService{}

// Default materializes spec.hostname from the object name so the published
// DNS identity is always explicit on the stored object. GenerateName creates
// are the one gap (no name at decode time); DNSHostname covers those and any
// client-side decode that skips scheme defaulting.
func (s *VPCService) Default() {
	if s.Spec.Hostname == "" {
		s.Spec.Hostname = s.Name
	}
}

var _ resourcestrategy.Validater = &VPCService{}
var _ resourcestrategy.ValidateUpdater = &VPCService{}

func (s *VPCService) Validate(ctx context.Context) field.ErrorList {
	return s.validate()
}

func (s *VPCService) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	// Allow finalizer removal on objects being deleted even if the spec is
	// no longer valid.
	if s.DeletionTimestamp != nil {
		return nil
	}
	// Ratchet: an update that doesn't touch the spec is not re-validated.
	// The status subresource strategy runs this same hook, so without the
	// ratchet a service admitted before a rule tightened would have its
	// status writes rejected and the reconciler would spin instead of
	// reporting the problem in Ready. Metadata-only edits and deletes on
	// such an object keep working too; a spec edit must fix it.
	if old, ok := obj.(*VPCService); ok && apiequality.Semantic.DeepEqual(old.Spec, s.Spec) {
		return nil
	}
	return s.validate()
}

// validate checks the shape of the fields a service needs to mean anything:
// the network it is scoped to, the selector that gives it members, and the
// DNS label it is published under. Cross-object state — hostname uniqueness
// within the network, and the referenced VPCNetwork actually existing — is
// enforced by admission plugins, not here.
func (s *VPCService) validate() field.ErrorList {
	var errs field.ErrorList

	// Membership and the published FQDN are both scoped to the network, so a
	// service without one selects nothing and has nowhere to be published.
	if s.Spec.NetworkRef.Name == "" {
		errs = append(errs, field.Required(field.NewPath("spec", "networkRef", "name"),
			"a VPCService is scoped to a VPCNetwork"))
	}

	// The selector is what makes a service a service. Which selectors are
	// usable is defined once, by MembershipSelector, so that what admission
	// rejects and what the reconciler refuses to act on cannot drift apart:
	// a selector this accepts but the reconciler treats as degenerate would
	// silently expand into the whole network.
	selectorPath := field.NewPath("spec", "selector")
	if _, err := s.Spec.MembershipSelector(); err != nil {
		if s.Spec.Selector == nil {
			errs = append(errs, field.Required(selectorPath,
				"a VPCService selects its member Tunnels by label; without a selector it can never have endpoints"))
		} else {
			errs = append(errs, field.Invalid(selectorPath, s.Spec.Selector, err.Error()))
		}
	}

	// The service is published as <hostname>.<network>.vpc.apoxy.net, so
	// anything that is not a single RFC 1123 label would produce an
	// unresolvable or ambiguous FQDN.
	if s.Spec.Hostname != "" {
		for _, msg := range validation.IsDNS1123Label(s.Spec.Hostname) {
			errs = append(errs, field.Invalid(field.NewPath("spec", "hostname"), s.Spec.Hostname, msg))
		}
	}

	return errs
}
