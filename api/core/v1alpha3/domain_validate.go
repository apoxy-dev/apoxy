package v1alpha3

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
}

var _ resourcestrategy.Validater = &Domain{}
var _ resourcestrategy.ValidateUpdater = &Domain{}

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
		hasIPs := r.Spec.Target.DNS.IPs != nil && len(r.Spec.Target.DNS.IPs.Addresses) > 0
		hasFQDN := r.Spec.Target.DNS.FQDN != nil
		if hasFQDN && hasIPs {
			errs = append(errs, field.Forbidden(field.NewPath("spec").Child("target").Child("dns").Child("fqdn"), "cannot set both FQDN and IPs in DNS target configuration"))
		}
		if r.Spec.Target.Ref != nil && (hasFQDN || hasIPs) {
			errs = append(errs, field.Forbidden(field.NewPath("spec").Child("target").Child("ref"), "cannot set both Ref and FQDN/IPs in DNS target configuration"))
		}
	}
	return errs
}
