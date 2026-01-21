package v1alpha2

import (
	"context"
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/rest"
)

var _ rest.Validater = &Backend{}
var _ rest.ValidateUpdater = &Backend{}

func (r *Backend) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *Backend) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	b := &Backend{}
	// XXX: Conversion needs to happen in apiserver-runtime before validation hooks are called.
	if mv, ok := obj.(resource.MultiVersionObject); ok {
		_ = mv.ConvertToStorageVersion(b)
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
