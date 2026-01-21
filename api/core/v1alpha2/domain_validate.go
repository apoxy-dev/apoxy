package v1alpha2

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/rest"
)

var _ rest.Defaulter = &Domain{}

// Default sets the default values for a Domain.
func (r *Domain) Default() {
	if r.Status.Phase == "" {
		r.Status.Phase = DomainPhasePending
	}
	if r.Spec.Target.DNS != nil && r.Spec.Target.DNS.TTL == nil {
		defaultTTL := int32(20)
		r.Spec.Target.DNS.TTL = &defaultTTL
	}
}

var _ rest.Validater = &Domain{}
var _ rest.ValidateUpdater = &Domain{}

func (r *Domain) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *Domain) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	// obj is the old object, r (receiver) is the new object being applied
	// We validate the new object (r), not the old one
	return r.validate()
}

func (r *Domain) validate() field.ErrorList {
	errs := field.ErrorList{}
	if r.Spec.TLS != nil {
		ca := r.Spec.TLS.CertificateAuthority
		if ca != "" && ca != "letsencrypt" {
			errs = append(errs, field.Forbidden(field.NewPath("spec").Child("tls").Child("certificateAuthority"), "unsupported certificate authority"))
		}
	}

	if r.Spec.Target.DNS != nil {
		if r.Spec.Target.DNS.FQDN != nil && len(r.Spec.Target.DNS.IPs) > 0 {
			errs = append(errs, field.Forbidden(field.NewPath("spec").Child("target").Child("dns").Child("fqdn"), "cannot set both FQDN and IPs in DNS target configuration"))
		}
		if r.Spec.Target.Ref != nil && (r.Spec.Target.DNS.FQDN != nil || len(r.Spec.Target.DNS.IPs) > 0) {
			errs = append(errs, field.Forbidden(field.NewPath("spec").Child("target").Child("ref"), "cannot set both Ref and FQDN/IPs in DNS target configuration"))
		}
	}
	return errs
}
