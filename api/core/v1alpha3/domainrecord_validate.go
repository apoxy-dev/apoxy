package v1alpha3

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

const (
	// DomainRecordMaxValues is the maximum number of values in one DomainRecord.
	DomainRecordMaxValues = 64
	// DomainRecordMaxValueBytes is the maximum length of one value in DNS zone file form.
	DomainRecordMaxValueBytes = 4096
)

var _ resourcestrategy.Defaulter = &DomainRecord{}

// Default sets the default values for a DomainRecord.
func (r *DomainRecord) Default() {
	if r.Spec.TTL == nil {
		defaultTTL := int32(300)
		r.Spec.TTL = &defaultTTL
	}
	// Default TLS for ref targets — ref targets always terminate TLS.
	if r.Spec.Target.Ref != nil && r.Spec.TLS == nil {
		r.Spec.TLS = &DomainTLSSpec{}
	}
}

var _ resourcestrategy.PrepareForCreater = &DomainRecord{}

// PrepareForCreate derives metadata.name from spec when the user omits it
// and sets status.type from the populated DNS field.
func (r *DomainRecord) PrepareForCreate(ctx context.Context) {
	r.GenerateName = ""
	if r.Name == "" {
		r.Name = r.derivedName()
	}
	r.Status.Type = deriveRecordType(r)
}

var _ resourcestrategy.PrepareForUpdater = &DomainRecord{}

// PrepareForUpdate re-derives status.type on updates.
func (r *DomainRecord) PrepareForUpdate(ctx context.Context, old runtime.Object) {
	r.Status.Type = deriveRecordType(r)
}

var _ resourcestrategy.Validater = &DomainRecord{}
var _ resourcestrategy.ValidateUpdater = &DomainRecord{}

func (r *DomainRecord) Validate(ctx context.Context) field.ErrorList {
	return append(r.validate(), r.validateLimits()...)
}

func (r *DomainRecord) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	// Allow finalizer removal on objects being deleted, even if the spec
	// is no longer valid (e.g. after a schema migration dropped fields).
	if r.DeletionTimestamp != nil {
		return nil
	}

	old := obj.(*DomainRecord)
	errs := r.validate()
	// A record stored before the limits keeps its values until they change.
	if !equality.Semantic.DeepEqual(r.Spec.Target.DNS, old.Spec.Target.DNS) {
		errs = append(errs, r.validateLimits()...)
	}

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
	oldKey := old.TargetFieldKey()
	newKey := r.TargetFieldKey()
	if oldKey != newKey {
		errs = append(errs, field.Forbidden(
			field.NewPath("spec", "target"),
			fmt.Sprintf("cannot change target field key from %q to %q", oldKey, newKey),
		))
	}

	// status.type is server-authoritative; reject updates that tamper with it.
	if expected := deriveRecordType(r); r.Status.Type != expected {
		errs = append(errs, field.Invalid(
			field.NewPath("status", "type"),
			r.Status.Type,
			fmt.Sprintf("must be %q (derived from spec)", expected),
		))
	}

	return errs
}

// derivedName returns the expected metadata.name for the record,
// derived from spec.name and the target field key.
func (r *DomainRecord) derivedName() string {
	if r.Spec.Name == "" {
		return ""
	}
	suffix := "ref"
	if r.Spec.Target.DNS != nil {
		if key := r.Spec.Target.DNS.DNSFieldKey(); key != "" {
			suffix = key
		}
	}
	return fmt.Sprintf("%s--%s", r.Spec.Name, suffix)
}

// TargetFieldKey returns the canonical target field key for a DomainRecord:
// "ref" for Ref targets, or the DNS field key (e.g. "a", "fqdn").
func (r *DomainRecord) TargetFieldKey() string {
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

	// metadata.name must match the derived name when explicitly set.
	expectedName := r.derivedName()
	if expectedName != "" && r.Name != expectedName {
		errs = append(errs, field.Invalid(
			field.NewPath("metadata", "name"),
			r.Name,
			fmt.Sprintf("must be %q (derived from spec)", expectedName),
		))
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

		dns := r.Spec.Target.DNS
		dnsPath := targetPath.Child("dns")
		for i, addr := range dns.A {
			ip := net.ParseIP(addr)
			if ip == nil || ip.To4() == nil {
				errs = append(errs, field.Invalid(
					dnsPath.Child("a").Index(i), addr,
					"must be a valid IPv4 address",
				))
			}
		}
		for i, addr := range dns.AAAA {
			ip := net.ParseIP(addr)
			if ip == nil || ip.To4() != nil {
				errs = append(errs, field.Invalid(
					dnsPath.Child("aaaa").Index(i), addr,
					"must be a valid IPv6 address",
				))
			}
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
		// Naming a CA while disabling issuance is contradictory; reject it
		// rather than silently honoring one half.
		if r.Spec.TLS.Disabled && ca != "" {
			errs = append(errs, field.Forbidden(specPath.Child("tls", "certificateAuthority"),
				"cannot be set when tls.disabled is true"))
		}
	}

	return errs
}

// validateLimits checks the value limits of the DNS servers.
func (r *DomainRecord) validateLimits() field.ErrorList {
	dns := r.Spec.Target.DNS
	if dns == nil {
		return nil
	}
	dnsPath := field.NewPath("spec", "target", "dns")
	errs := field.ErrorList{}
	total := 0
	check := func(key string, values []string, text bool) {
		total += len(values)
		for i, v := range values {
			n := len(v)
			if text {
				n = zoneFileTextBytes(v)
			}
			if n > DomainRecordMaxValueBytes {
				e := field.TooLong(dnsPath.Child(key).Index(i), nil, DomainRecordMaxValueBytes)
				e.Detail = fmt.Sprintf("must have at most %d bytes in DNS zone file form, not %d", DomainRecordMaxValueBytes, n)
				errs = append(errs, e)
			}
		}
	}
	check("a", dns.A, false)
	check("aaaa", dns.AAAA, false)
	if dns.FQDN != nil {
		check("fqdn", []string{*dns.FQDN}, false)
	}
	check("txt", dns.TXT, true)
	check("mx", dns.MX, false)
	check("dkim", dns.DKIM, true)
	check("spf", dns.SPF, true)
	check("dmarc", dns.DMARC, true)
	check("caa", dns.CAA, false)
	check("srv", dns.SRV, false)
	check("ns", dns.NS, false)
	check("ds", dns.DS, false)
	check("dnskey", dns.DNSKEY, false)
	if total > DomainRecordMaxValues {
		errs = append(errs, field.TooMany(dnsPath, total, DomainRecordMaxValues))
	}
	return errs
}

// zoneFileTextBytes returns the length of a TXT value in zone file form: the
// Go-quoted value in quoted strings of 255 bytes, with zone file escapes.
func zoneFileTextBytes(v string) int {
	q := strconv.Quote(v)
	q = q[1 : len(q)-1]
	parsed, n := 0, 0
	for i := 0; i < len(q); i++ {
		b := q[i]
		if b == '\\' {
			// The zone file reads a backslash and the next byte as that byte.
			i++
			b = q[i]
		}
		parsed++
		switch {
		case b == '"' || b == '\\':
			n += 2
		case b < ' ' || b > '~':
			n += 4
		default:
			n++
		}
	}
	return n + 3*max(1, (parsed+254)/255) - 1
}
