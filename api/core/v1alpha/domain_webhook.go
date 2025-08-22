package v1alpha

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &Domain{}

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

var _ resourcestrategy.Validater = &Domain{}
var _ resourcestrategy.ValidateUpdater = &Domain{}

func (r *Domain) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *Domain) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	d := obj.(*Domain)
	return d.validate()
}

func (r *Domain) validate() field.ErrorList {
	errs := field.ErrorList{}
	if r.Spec.TLS != nil {
		ca := r.Spec.TLS.CertificateAuthority
		if ca != "" && ca != "letsencrypt" {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("tls").Child("certificateAuthority"), r, "unsupported certificate authority"))
		}
	}

	if r.Spec.Target.DNS != nil {
		if r.Spec.Target.DNS.FQDN != nil && len(r.Spec.Target.DNS.IPs) > 0 {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("target").Child("dns").Child("fqdn"), r, "cannot set both FQDN and IPs in DNS target configuration"))
		}
		if r.Spec.Target.Ref != nil && (r.Spec.Target.DNS.FQDN != nil || len(r.Spec.Target.DNS.IPs) > 0) {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("target").Child("ref"), r, "cannot set both Ref and FQDN/IPs in DNS target configuration"))
		}
	}
	return errs
}
