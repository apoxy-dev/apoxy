package v1alpha1

import (
	"context"

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
	return s.validate()
}

// validate checks that spec.hostname (when set) is a usable DNS label: the
// service is published as <hostname>.<network>.vpc.apoxy.net, so anything
// that is not a single RFC 1123 label would produce an unresolvable or
// ambiguous FQDN. Uniqueness within the VPCNetwork is cross-object state and
// is enforced by an admission plugin, not here.
func (s *VPCService) validate() field.ErrorList {
	var errs field.ErrorList
	if s.Spec.Hostname != "" {
		for _, msg := range validation.IsDNS1123Label(s.Spec.Hostname) {
			errs = append(errs, field.Invalid(field.NewPath("spec", "hostname"), s.Spec.Hostname, msg))
		}
	}
	return errs
}
