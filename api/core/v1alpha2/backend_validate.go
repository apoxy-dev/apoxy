package v1alpha2

import (
	"context"
	"fmt"
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/apoxy-dev/apoxy/api/resource"
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &Backend{}
var _ resourcestrategy.Validater = &Backend{}
var _ resourcestrategy.ValidateUpdater = &Backend{}

// Default normalizes user-supplied fields before validation. The xDS
// translator switches on Spec.Protocol case-sensitively, so a stray "H2"
// would silently drop the upstream TLS context and Envoy would send
// plaintext to port 443. Lowercase on write to match the enum.
func (r *Backend) Default() {
	r.Spec.Protocol = BackendProto(strings.ToLower(string(r.Spec.Protocol)))
}

func (r *Backend) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *Backend) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	b := &Backend{}
	// XXX: Conversion needs to happen in apiserver-runtime before validation hooks are called.
	if mv, ok := obj.(resource.MultiVersionObject); ok {
		mv.ConvertToStorageVersion(b)
	} else if b, ok = obj.(*Backend); !ok {
		return field.ErrorList{
			field.Invalid(field.NewPath("kind"), obj.GetObjectKind().GroupVersionKind().Kind, "expected Backend"),
		}
	}

	return b.validate()
}

func (r *Backend) validate() field.ErrorList {
	errs := field.ErrorList{}

	if r.Spec.DynamicProxy != nil && len(r.Spec.Endpoints) == 0 {
		errs = append(errs, field.Required(field.NewPath("spec", "endpoints"), "endpoints cannot be empty"))
	}
	if r.Spec.DynamicProxy != nil && len(r.Spec.Endpoints) > 1 {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "endpoints"), "only one endpoint can be specified"))
	}

	for i, endpoint := range r.Spec.Endpoints {
		if endpoint.IP != "" && endpoint.FQDN != "" {
			errs = append(errs, field.Forbidden(field.NewPath("spec", "endpoints", fmt.Sprintf("[%d]", i), "ip"), "ip and fqdn cannot be specified together"))
		}

		if endpoint.IP != "" {
			if net.ParseIP(endpoint.IP) == nil {
				errs = append(errs, field.Invalid(field.NewPath("spec", "endpoints", fmt.Sprintf("[%d]", i), "ip"), endpoint.IP, "invalid ip address"))
			}
		} else if endpoint.FQDN != "" {
			errs = append(errs, validation.IsFullyQualifiedDomainName(field.NewPath("spec", "endpoints", fmt.Sprintf("[%d]", i), "fqdn"), endpoint.FQDN)...)
		}
	}

	return errs
}
