package admission

import (
	"context"
	"fmt"
	"io"
	"net"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/rest"

	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
	a3yclient "github.com/apoxy-dev/apoxy/client/versioned"
	corev1alpha3typed "github.com/apoxy-dev/apoxy/client/versioned/typed/core/v1alpha3"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	// ReflectedAnnotation marks objects created by the reflection system.
	ReflectedAnnotation = "core.apoxy.dev/reflected"

	domainRecordReflectionPluginName = "DomainRecordReflection"
)

var (
	domainGVR = schema.GroupVersionResource{
		Group:    corev1alpha3.SchemeGroupVersion.Group,
		Version:  corev1alpha3.SchemeGroupVersion.Version,
		Resource: "domains",
	}
	domainRecordGVR = schema.GroupVersionResource{
		Group:    corev1alpha3.SchemeGroupVersion.Group,
		Version:  corev1alpha3.SchemeGroupVersion.Version,
		Resource: "domainrecords",
	}
)

// DomainRecordReflection is an admission plugin that keeps Domain and
// DomainRecord resources in sync. Creating/updating a Domain produces
// reflected DomainRecords; creating/updating a standalone DomainRecord
// produces a reflected Domain.
type DomainRecordReflection struct {
	*admission.Handler
	client a3yclient.Interface
}

var _ admission.MutationInterface = &DomainRecordReflection{}

// NewDomainRecordReflectionFactory returns an admission.Factory for the plugin.
// The client is created eagerly from clientConfig because the apiserver-runtime
// builder overwrites ExtraAdmissionInitializers in its Config() method,
// preventing the standard PluginInitializer injection from reaching our plugin.
func NewDomainRecordReflectionFactory(clientConfig *rest.Config) admission.Factory {
	return func(_ io.Reader) (admission.Interface, error) {
		client, err := a3yclient.NewForConfig(clientConfig)
		if err != nil {
			return nil, fmt.Errorf("creating apoxy client for admission: %w", err)
		}
		return &DomainRecordReflection{
			Handler: admission.NewHandler(admission.Create, admission.Update, admission.Delete),
			client:  client,
		}, nil
	}
}

func (p *DomainRecordReflection) ValidateInitialization() error {
	if p.client == nil {
		return fmt.Errorf("missing apoxy client")
	}
	return nil
}

// Admit handles the admission request.
func (p *DomainRecordReflection) Admit(
	ctx context.Context,
	a admission.Attributes,
	_ admission.ObjectInterfaces,
) error {
	// Only act on v1alpha3 storage-version resources.
	gvr := a.GetResource()
	switch gvr {
	case domainGVR:
		return p.admitDomain(ctx, a)
	case domainRecordGVR:
		return p.admitDomainRecord(ctx, a)
	default:
		return nil
	}
}

func isReflected(obj metav1.Object) bool {
	if obj == nil {
		return false
	}
	ann := obj.GetAnnotations()
	return ann != nil && ann[ReflectedAnnotation] == "true"
}

func setReflected(obj metav1.Object) {
	ann := obj.GetAnnotations()
	if ann == nil {
		ann = make(map[string]string)
	}
	ann[ReflectedAnnotation] = "true"
	obj.SetAnnotations(ann)
}

// admitDomain handles Domain CREATE/UPDATE/DELETE and reflects DomainRecords.
func (p *DomainRecordReflection) admitDomain(ctx context.Context, a admission.Attributes) error {
	switch a.GetOperation() {
	case admission.Create, admission.Update:
		domain, ok := a.GetObject().(*corev1alpha3.Domain)
		if !ok {
			return nil
		}
		if isReflected(domain) {
			return nil
		}
		return p.reflectDomainToRecords(ctx, domain)

	case admission.Delete:
		// On delete, clean up reflected DomainRecords.
		name := a.GetName()
		if name == "" {
			return nil
		}
		// Check if the domain being deleted is user-managed (non-reflected).
		// Only user-managed domains have reflected DomainRecords to clean up.
		return p.deleteReflectedDomainRecords(ctx, name)

	default:
		return nil
	}
}

// admitDomainRecord handles DomainRecord CREATE/UPDATE/DELETE and reflects Domains.
func (p *DomainRecordReflection) admitDomainRecord(ctx context.Context, a admission.Attributes) error {
	switch a.GetOperation() {
	case admission.Create, admission.Update:
		dr, ok := a.GetObject().(*corev1alpha3.DomainRecord)
		if !ok {
			return nil
		}
		if isReflected(dr) {
			return nil
		}
		return p.reflectDomainRecordToDomain(ctx, dr)

	case admission.Delete:
		name := a.GetName()
		if name == "" {
			return nil
		}
		return p.handleDomainRecordDelete(ctx, name)

	default:
		return nil
	}
}

// reflectDomainToRecords creates/updates/deletes reflected DomainRecords for a Domain.
func (p *DomainRecordReflection) reflectDomainToRecords(ctx context.Context, domain *corev1alpha3.Domain) error {
	client := p.client.CoreV1alpha3().DomainRecords()

	desired := DomainToDomainRecords(domain)

	// Build a map of desired records by name.
	desiredByName := make(map[string]*corev1alpha3.DomainRecord, len(desired))
	for i := range desired {
		desiredByName[desired[i].Name] = &desired[i]
	}

	// List existing reflected DomainRecords for this domain.
	existing, err := listReflectedDomainRecords(ctx, client, domain.Name)
	if err != nil {
		return fmt.Errorf("listing reflected domain records: %w", err)
	}
	existingByName := make(map[string]*corev1alpha3.DomainRecord, len(existing))
	for i := range existing {
		existingByName[existing[i].Name] = &existing[i]
	}

	// Create missing / update changed.
	for name, want := range desiredByName {
		if have, ok := existingByName[name]; ok {
			// Update if spec differs.
			if !domainRecordSpecEqual(have, want) {
				have.Spec = want.Spec
				if _, err := client.Update(ctx, have, metav1.UpdateOptions{}); err != nil {
					return fmt.Errorf("updating reflected domain record %s: %w", name, err)
				}
				log.Infof("Updated reflected DomainRecord %s for Domain %s", name, domain.Name)
			}
		} else {
			if _, err := client.Create(ctx, want, metav1.CreateOptions{}); err != nil {
				if kerrors.IsAlreadyExists(err) {
					continue
				}
				return fmt.Errorf("creating reflected domain record %s: %w", name, err)
			}
			log.Infof("Created reflected DomainRecord %s for Domain %s", name, domain.Name)
		}
	}

	// Delete stale.
	for name, have := range existingByName {
		if _, ok := desiredByName[name]; !ok {
			if err := client.Delete(ctx, have.Name, metav1.DeleteOptions{}); err != nil && !kerrors.IsNotFound(err) {
				return fmt.Errorf("deleting stale reflected domain record %s: %w", name, err)
			}
			log.Infof("Deleted stale reflected DomainRecord %s for Domain %s", name, domain.Name)
		}
	}

	return nil
}

// deleteReflectedDomainRecords removes all reflected DomainRecords for a deleted Domain.
func (p *DomainRecordReflection) deleteReflectedDomainRecords(ctx context.Context, domainName string) error {
	client := p.client.CoreV1alpha3().DomainRecords()
	records, err := listReflectedDomainRecords(ctx, client, domainName)
	if err != nil {
		return fmt.Errorf("listing reflected domain records for cleanup: %w", err)
	}
	for i := range records {
		if err := client.Delete(ctx, records[i].Name, metav1.DeleteOptions{}); err != nil && !kerrors.IsNotFound(err) {
			return fmt.Errorf("deleting reflected domain record %s: %w", records[i].Name, err)
		}
		log.Infof("Deleted reflected DomainRecord %s (Domain %s deleted)", records[i].Name, domainName)
	}
	return nil
}

// reflectDomainRecordToDomain creates/updates a reflected Domain from standalone DomainRecords.
func (p *DomainRecordReflection) reflectDomainRecordToDomain(ctx context.Context, dr *corev1alpha3.DomainRecord) error {
	domainName := dr.Spec.Name
	if domainName == "" {
		return nil
	}

	domainClient := p.client.CoreV1alpha3().Domains()
	drClient := p.client.CoreV1alpha3().DomainRecords()

	// Check if a user-managed Domain already exists.
	existing, err := domainClient.Get(ctx, domainName, metav1.GetOptions{})
	if err == nil {
		// Domain exists — only update if it's reflected.
		if !isReflected(existing) {
			return nil
		}
	} else if !kerrors.IsNotFound(err) {
		return fmt.Errorf("getting domain %s: %w", domainName, err)
	}

	// List all primary (non-reflected) DomainRecords with this spec.name.
	primaries, err := listPrimaryDomainRecords(ctx, drClient, domainName)
	if err != nil {
		return fmt.Errorf("listing primary domain records for %s: %w", domainName, err)
	}

	// Include the current record being admitted (it may not be persisted yet).
	primaries = ensureRecordInList(primaries, dr)

	if len(primaries) == 0 {
		return nil
	}

	spec := DomainRecordsToDomainSpec(primaries)

	if existing != nil && isReflected(existing) {
		// Update.
		existing.Spec = spec
		if _, err := domainClient.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("updating reflected domain %s: %w", domainName, err)
		}
		log.Infof("Updated reflected Domain %s from DomainRecord", domainName)
	} else {
		// Create.
		domain := &corev1alpha3.Domain{
			ObjectMeta: metav1.ObjectMeta{
				Name: domainName,
			},
			Spec: spec,
		}
		setReflected(domain)
		if _, err := domainClient.Create(ctx, domain, metav1.CreateOptions{}); err != nil {
			if kerrors.IsAlreadyExists(err) {
				return nil
			}
			return fmt.Errorf("creating reflected domain %s: %w", domainName, err)
		}
		log.Infof("Created reflected Domain %s from DomainRecord", domainName)
	}
	return nil
}

// handleDomainRecordDelete handles deletion of a primary DomainRecord.
func (p *DomainRecordReflection) handleDomainRecordDelete(ctx context.Context, drName string) error {
	drClient := p.client.CoreV1alpha3().DomainRecords()
	domainClient := p.client.CoreV1alpha3().Domains()

	// Get the DomainRecord being deleted to find the domain name.
	dr, err := drClient.Get(ctx, drName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting domain record %s: %w", drName, err)
	}

	// Skip reflected records — they're managed by the Domain side.
	if isReflected(dr) {
		return nil
	}

	domainName := dr.Spec.Name
	if domainName == "" {
		return nil
	}

	// Check if there's a reflected Domain.
	existing, err := domainClient.Get(ctx, domainName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting domain %s: %w", domainName, err)
	}
	if !isReflected(existing) {
		return nil
	}

	// List remaining primary DomainRecords (excluding the one being deleted).
	primaries, err := listPrimaryDomainRecords(ctx, drClient, domainName)
	if err != nil {
		return fmt.Errorf("listing primary domain records for %s: %w", domainName, err)
	}
	remaining := excludeRecord(primaries, drName)

	if len(remaining) == 0 {
		// No more primary records — delete the reflected Domain.
		if err := domainClient.Delete(ctx, domainName, metav1.DeleteOptions{}); err != nil && !kerrors.IsNotFound(err) {
			return fmt.Errorf("deleting reflected domain %s: %w", domainName, err)
		}
		log.Infof("Deleted reflected Domain %s (last DomainRecord removed)", domainName)
	} else {
		// Re-merge remaining records.
		existing.Spec = DomainRecordsToDomainSpec(remaining)
		if _, err := domainClient.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("updating reflected domain %s: %w", domainName, err)
		}
		log.Infof("Updated reflected Domain %s after DomainRecord deletion", domainName)
	}
	return nil
}

// listReflectedDomainRecords returns DomainRecords that were reflected from the
// given Domain (identified by spec.name prefix and reflected annotation).
func listReflectedDomainRecords(
	ctx context.Context,
	client corev1alpha3typed.DomainRecordInterface,
	domainName string,
) ([]corev1alpha3.DomainRecord, error) {
	all, err := client.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var result []corev1alpha3.DomainRecord
	for i := range all.Items {
		r := &all.Items[i]
		if r.Spec.Name == domainName && isReflected(r) {
			result = append(result, *r)
		}
	}
	return result, nil
}

// listPrimaryDomainRecords returns non-reflected DomainRecords with the given spec.name.
func listPrimaryDomainRecords(
	ctx context.Context,
	client corev1alpha3typed.DomainRecordInterface,
	domainName string,
) ([]corev1alpha3.DomainRecord, error) {
	all, err := client.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var result []corev1alpha3.DomainRecord
	for i := range all.Items {
		r := &all.Items[i]
		if r.Spec.Name == domainName && !isReflected(r) {
			result = append(result, *r)
		}
	}
	return result, nil
}

// ensureRecordInList adds dr to the list if it's not already present (by name).
func ensureRecordInList(list []corev1alpha3.DomainRecord, dr *corev1alpha3.DomainRecord) []corev1alpha3.DomainRecord {
	// The record being admitted may not be in the list yet if it's a CREATE.
	// For an UPDATE, it might be there with old data — replace it.
	found := false
	for i := range list {
		if list[i].Name == dr.Name {
			list[i] = *dr
			found = true
			break
		}
	}
	if !found {
		list = append(list, *dr)
	}
	return list
}

// excludeRecord filters out a record by name.
func excludeRecord(list []corev1alpha3.DomainRecord, name string) []corev1alpha3.DomainRecord {
	result := make([]corev1alpha3.DomainRecord, 0, len(list))
	for i := range list {
		if list[i].Name != name {
			result = append(result, list[i])
		}
	}
	return result
}

// domainRecordSpecEqual checks if two DomainRecord specs are equal for reflection purposes.
func domainRecordSpecEqual(a, b *corev1alpha3.DomainRecord) bool {
	// Compare zone.
	if a.Spec.Zone != b.Spec.Zone {
		return false
	}
	// Compare name.
	if a.Spec.Name != b.Spec.Name {
		return false
	}
	// Compare TTL.
	if !int32PtrEqual(a.Spec.TTL, b.Spec.TTL) {
		return false
	}
	// Compare TLS.
	if !tlsSpecEqual(a.Spec.TLS, b.Spec.TLS) {
		return false
	}
	// Compare target.ref.
	if !refEqual(a.Spec.Target.Ref, b.Spec.Target.Ref) {
		return false
	}
	// Compare target.dns.
	if !dnsTargetEqual(a.Spec.Target.DNS, b.Spec.Target.DNS) {
		return false
	}
	return true
}

func int32PtrEqual(a, b *int32) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func tlsSpecEqual(a, b *corev1alpha3.DomainTLSSpec) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.CertificateAuthority == b.CertificateAuthority
}

func refEqual(a, b *corev1alpha3.LocalObjectReference) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Group == b.Group && a.Kind == b.Kind && a.Name == b.Name
}

func dnsTargetEqual(a, b *corev1alpha3.DomainRecordTargetDNS) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if !stringSliceEqual(a.A, b.A) {
		return false
	}
	if !stringSliceEqual(a.AAAA, b.AAAA) {
		return false
	}
	if !stringPtrEqual(a.FQDN, b.FQDN) {
		return false
	}
	if !stringSliceEqual(a.TXT, b.TXT) {
		return false
	}
	if !stringSliceEqual(a.MX, b.MX) {
		return false
	}
	if !stringSliceEqual(a.DKIM, b.DKIM) {
		return false
	}
	if !stringSliceEqual(a.SPF, b.SPF) {
		return false
	}
	if !stringSliceEqual(a.DMARC, b.DMARC) {
		return false
	}
	if !stringSliceEqual(a.CAA, b.CAA) {
		return false
	}
	if !stringSliceEqual(a.SRV, b.SRV) {
		return false
	}
	if !stringSliceEqual(a.NS, b.NS) {
		return false
	}
	if !stringSliceEqual(a.DS, b.DS) {
		return false
	}
	if !stringSliceEqual(a.DNSKEY, b.DNSKEY) {
		return false
	}
	return true
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// DomainToDomainRecords converts a Domain into the set of reflected DomainRecords.
func DomainToDomainRecords(domain *corev1alpha3.Domain) []corev1alpha3.DomainRecord {
	var records []corev1alpha3.DomainRecord

	// Ref target → one DomainRecord.
	if domain.Spec.Target.Ref != nil {
		dr := corev1alpha3.DomainRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s--ref", domain.Name),
			},
			Spec: corev1alpha3.DomainRecordSpec{
				Zone: domain.Spec.Zone,
				Name: domain.Name,
				Target: corev1alpha3.DomainRecordTarget{
					Ref: domain.Spec.Target.Ref.DeepCopy(),
				},
				TLS: domain.Spec.TLS.DeepCopy(),
			},
		}
		setReflected(&dr)
		records = append(records, dr)
	}

	// DNS target → one DomainRecord per populated field.
	if domain.Spec.Target.DNS != nil {
		dns := domain.Spec.Target.DNS

		if dns.IPs != nil && len(dns.IPs.Addresses) > 0 {
			var v4, v6 []string
			for _, addr := range dns.IPs.Addresses {
				ip := net.ParseIP(addr)
				if ip == nil {
					continue
				}
				if ip.To4() == nil {
					v6 = append(v6, addr)
				} else {
					v4 = append(v4, addr)
				}
			}
			if len(v4) > 0 {
				dr := newDNSRecord(domain, "a", dns.IPs.TTL)
				dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
					A: v4,
				}
				records = append(records, dr)
			}
			if len(v6) > 0 {
				dr := newDNSRecord(domain, "aaaa", dns.IPs.TTL)
				dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
					AAAA: v6,
				}
				records = append(records, dr)
			}
		}
		if dns.FQDN != nil {
			dr := newDNSRecord(domain, "fqdn", dns.FQDN.TTL)
			fqdn := dns.FQDN.Name
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				FQDN: &fqdn,
			}
			records = append(records, dr)
		}
		if dns.TXT != nil && len(dns.TXT.Values) > 0 {
			dr := newDNSRecord(domain, "txt", dns.TXT.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				TXT: append([]string(nil), dns.TXT.Values...),
			}
			records = append(records, dr)
		}
		if dns.MX != nil && len(dns.MX.Values) > 0 {
			dr := newDNSRecord(domain, "mx", dns.MX.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				MX: append([]string(nil), dns.MX.Values...),
			}
			records = append(records, dr)
		}
		if dns.DKIM != nil && len(dns.DKIM.Values) > 0 {
			dr := newDNSRecord(domain, "dkim", dns.DKIM.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				DKIM: append([]string(nil), dns.DKIM.Values...),
			}
			records = append(records, dr)
		}
		if dns.SPF != nil && len(dns.SPF.Values) > 0 {
			dr := newDNSRecord(domain, "spf", dns.SPF.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				SPF: append([]string(nil), dns.SPF.Values...),
			}
			records = append(records, dr)
		}
		if dns.DMARC != nil && len(dns.DMARC.Values) > 0 {
			dr := newDNSRecord(domain, "dmarc", dns.DMARC.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				DMARC: append([]string(nil), dns.DMARC.Values...),
			}
			records = append(records, dr)
		}
		if dns.CAA != nil && len(dns.CAA.Values) > 0 {
			dr := newDNSRecord(domain, "caa", dns.CAA.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				CAA: append([]string(nil), dns.CAA.Values...),
			}
			records = append(records, dr)
		}
		if dns.SRV != nil && len(dns.SRV.Values) > 0 {
			dr := newDNSRecord(domain, "srv", dns.SRV.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				SRV: append([]string(nil), dns.SRV.Values...),
			}
			records = append(records, dr)
		}
		if dns.NS != nil && len(dns.NS.Nameservers) > 0 {
			dr := newDNSRecord(domain, "ns", dns.NS.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				NS: append([]string(nil), dns.NS.Nameservers...),
			}
			records = append(records, dr)
		}
		if dns.DS != nil && len(dns.DS.Values) > 0 {
			dr := newDNSRecord(domain, "ds", dns.DS.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				DS: append([]string(nil), dns.DS.Values...),
			}
			records = append(records, dr)
		}
		if dns.DNSKEY != nil && len(dns.DNSKEY.Values) > 0 {
			dr := newDNSRecord(domain, "dnskey", dns.DNSKEY.TTL)
			dr.Spec.Target.DNS = &corev1alpha3.DomainRecordTargetDNS{
				DNSKEY: append([]string(nil), dns.DNSKEY.Values...),
			}
			records = append(records, dr)
		}
	}

	// Custom domains → one DomainRecord each.
	for _, cd := range domain.Spec.CustomDomains {
		dr := corev1alpha3.DomainRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s--ref", cd),
			},
			Spec: corev1alpha3.DomainRecordSpec{
				Name: cd,
				Target: corev1alpha3.DomainRecordTarget{
					Ref: &corev1alpha3.LocalObjectReference{
						Group: corev1alpha3.Group(corev1alpha3.SchemeGroupVersion.Group),
						Kind:  "DomainRecord",
						Name:  corev1alpha3.ObjectName(fmt.Sprintf("%s--ref", domain.Name)),
					},
				},
				TLS: domain.Spec.TLS.DeepCopy(),
			},
		}
		setReflected(&dr)
		records = append(records, dr)
	}

	return records
}

// newDNSRecord creates a base reflected DomainRecord for a DNS field.
func newDNSRecord(domain *corev1alpha3.Domain, fieldKey string, ttl *int32) corev1alpha3.DomainRecord {
	dr := corev1alpha3.DomainRecord{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s--%s", domain.Name, fieldKey),
		},
		Spec: corev1alpha3.DomainRecordSpec{
			Zone: domain.Spec.Zone,
			Name: domain.Name,
			TTL:  copyInt32Ptr(ttl),
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{},
			},
		},
	}
	setReflected(&dr)
	return dr
}

func copyInt32Ptr(p *int32) *int32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// DomainRecordsToDomainSpec merges a list of primary DomainRecords into a DomainSpec.
func DomainRecordsToDomainSpec(records []corev1alpha3.DomainRecord) corev1alpha3.DomainSpec {
	spec := corev1alpha3.DomainSpec{}

	for i := range records {
		r := &records[i]

		// Pick zone from any record.
		if spec.Zone == "" && r.Spec.Zone != "" {
			spec.Zone = r.Spec.Zone
		}

		// Custom domain: standalone record (zone="") with a ref target
		// pointing to a DomainRecord.
		if r.Spec.Zone == "" && r.Spec.Target.Ref != nil &&
			r.Spec.Target.Ref.Kind == "DomainRecord" {
			spec.CustomDomains = append(spec.CustomDomains, r.Spec.Name)
			if r.Spec.TLS != nil && spec.TLS == nil {
				spec.TLS = r.Spec.TLS.DeepCopy()
			}
			continue
		}

		// Ref target.
		if r.Spec.Target.Ref != nil {
			spec.Target.Ref = r.Spec.Target.Ref.DeepCopy()
			if r.Spec.TLS != nil {
				spec.TLS = r.Spec.TLS.DeepCopy()
			}
			continue
		}

		// DNS target.
		if r.Spec.Target.DNS == nil {
			continue
		}
		if spec.Target.DNS == nil {
			spec.Target.DNS = &corev1alpha3.DomainTargetDNS{}
		}

		dns := r.Spec.Target.DNS
		if len(dns.A) > 0 || len(dns.AAAA) > 0 {
			if spec.Target.DNS.IPs == nil {
				spec.Target.DNS.IPs = &corev1alpha3.DNSAddressRecords{
					TTL: copyInt32Ptr(r.Spec.TTL),
				}
			}
			spec.Target.DNS.IPs.Addresses = append(spec.Target.DNS.IPs.Addresses, dns.A...)
			spec.Target.DNS.IPs.Addresses = append(spec.Target.DNS.IPs.Addresses, dns.AAAA...)
		}
		if dns.FQDN != nil {
			fqdn := *dns.FQDN
			spec.Target.DNS.FQDN = &corev1alpha3.DNSCNAMERecord{
				Name: fqdn,
				TTL:  copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.TXT) > 0 {
			spec.Target.DNS.TXT = &corev1alpha3.DNSTXTRecords{
				Values: append([]string(nil), dns.TXT...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.MX) > 0 {
			spec.Target.DNS.MX = &corev1alpha3.DNSMXRecords{
				Values: append([]string(nil), dns.MX...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.DKIM) > 0 {
			spec.Target.DNS.DKIM = &corev1alpha3.DNSDKIMRecords{
				Values: append([]string(nil), dns.DKIM...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.SPF) > 0 {
			spec.Target.DNS.SPF = &corev1alpha3.DNSSPFRecords{
				Values: append([]string(nil), dns.SPF...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.DMARC) > 0 {
			spec.Target.DNS.DMARC = &corev1alpha3.DNSDMARCRecords{
				Values: append([]string(nil), dns.DMARC...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.CAA) > 0 {
			spec.Target.DNS.CAA = &corev1alpha3.DNSCAARecords{
				Values: append([]string(nil), dns.CAA...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.SRV) > 0 {
			spec.Target.DNS.SRV = &corev1alpha3.DNSSRVRecords{
				Values: append([]string(nil), dns.SRV...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.NS) > 0 {
			spec.Target.DNS.NS = &corev1alpha3.DNSNSRecords{
				Nameservers: append([]string(nil), dns.NS...),
				TTL:         copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.DS) > 0 {
			spec.Target.DNS.DS = &corev1alpha3.DNSDSRecords{
				Values: append([]string(nil), dns.DS...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
		if len(dns.DNSKEY) > 0 {
			spec.Target.DNS.DNSKEY = &corev1alpha3.DNSDNSKEYRecords{
				Values: append([]string(nil), dns.DNSKEY...),
				TTL:    copyInt32Ptr(r.Spec.TTL),
			}
		}
	}

	return spec
}
