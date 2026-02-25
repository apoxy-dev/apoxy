package v1alpha3

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &DomainRecord{}

// Default sets the default values for a DomainRecord.
func (r *DomainRecord) Default() {
	if r.Spec.TTL == nil {
		defaultTTL := int32(300)
		r.Spec.TTL = &defaultTTL
	}
}

var _ resourcestrategy.PrepareForCreater = &DomainRecord{}

// PrepareForCreate generates metadata.name from spec.name and the target field key.
func (r *DomainRecord) PrepareForCreate(ctx context.Context) {
	suffix := "ref"
	if r.Spec.Target.DNS != nil {
		if key := r.Spec.Target.DNS.DNSFieldKey(); key != "" {
			suffix = key
		}
	}
	r.Name = fmt.Sprintf("%s.%s", r.Spec.Name, suffix)
	r.GenerateName = ""
}

var _ resourcestrategy.Validater = &DomainRecord{}
var _ resourcestrategy.ValidateUpdater = &DomainRecord{}

func (r *DomainRecord) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *DomainRecord) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	old := obj.(*DomainRecord)
	errs := r.validate()

	// Reject changes to spec.name.
	if r.Spec.Name != old.Spec.Name {
		errs = append(errs, field.Forbidden(
			field.NewPath("spec", "name"),
			"field is immutable after creation",
		))
	}

	// Reject changes to spec.zone.
	if r.Spec.Zone != old.Spec.Zone {
		errs = append(errs, field.Forbidden(
			field.NewPath("spec", "zone"),
			"field is immutable after creation",
		))
	}

	// Reject changes to the target field key (e.g. switching from ips to txt).
	oldKey := targetFieldKey(old)
	newKey := targetFieldKey(r)
	if oldKey != newKey {
		errs = append(errs, field.Forbidden(
			field.NewPath("spec", "target"),
			fmt.Sprintf("cannot change target field key from %q to %q", oldKey, newKey),
		))
	}

	return errs
}

// targetFieldKey returns the target field key for a DomainRecord.
func targetFieldKey(r *DomainRecord) string {
	if r.Spec.Target.Ref != nil {
		return "ref"
	}
	if r.Spec.Target.DNS != nil {
		return r.Spec.Target.DNS.DNSFieldKey()
	}
	return ""
}

func (r *DomainRecord) validate() field.ErrorList {
	errs := field.ErrorList{}
	specPath := field.NewPath("spec")

	// spec.name is required.
	if r.Spec.Name == "" {
		errs = append(errs, field.Required(specPath.Child("name"), "DNS record name is required"))
	} else {
		// Basic DNS name validation: must be <= 253 chars, segments <= 63 chars.
		if len(r.Spec.Name) > 253 {
			errs = append(errs, field.Invalid(specPath.Child("name"), r.Spec.Name, "must be no more than 253 characters"))
		}
		for _, label := range strings.Split(r.Spec.Name, ".") {
			if len(label) > 63 {
				errs = append(errs, field.Invalid(specPath.Child("name"), r.Spec.Name, "each label must be no more than 63 characters"))
				break
			}
		}
	}

	// TTL range validation.
	if r.Spec.TTL != nil {
		if *r.Spec.TTL < 0 || *r.Spec.TTL > 86400 {
			errs = append(errs, field.Invalid(specPath.Child("ttl"), *r.Spec.TTL, "must be between 0 and 86400"))
		}
	}

	targetPath := specPath.Child("target")

	// Target: exactly one of DNS or Ref must be set.
	hasDNS := r.Spec.Target.DNS != nil
	hasRef := r.Spec.Target.Ref != nil
	if !hasDNS && !hasRef {
		errs = append(errs, field.Required(targetPath, "exactly one of dns or ref must be set"))
	}
	if hasDNS && hasRef {
		errs = append(errs, field.Forbidden(targetPath, "cannot set both dns and ref"))
	}

	// When DNS is set, exactly one field must be populated.
	if hasDNS {
		count := r.Spec.Target.DNS.PopulatedFieldCount()
		if count == 0 {
			errs = append(errs, field.Required(targetPath.Child("dns"), "exactly one DNS field must be populated"))
		}
		if count > 1 {
			errs = append(errs, field.Forbidden(targetPath.Child("dns"), "exactly one DNS field must be populated, found multiple"))
		}
	}

	// tls is only valid when target.ref is set.
	if r.Spec.TLS != nil && !hasRef {
		errs = append(errs, field.Forbidden(specPath.Child("tls"), "tls is only valid when target.ref is set"))
	}

	// Validate TLS certificate authority if set.
	if r.Spec.TLS != nil {
		ca := r.Spec.TLS.CertificateAuthority
		if ca != "" && ca != "letsencrypt" {
			errs = append(errs, field.Forbidden(specPath.Child("tls", "certificateAuthority"), "unsupported certificate authority"))
		}
	}

	return errs
}
