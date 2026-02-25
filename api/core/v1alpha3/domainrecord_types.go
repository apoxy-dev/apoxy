package v1alpha3

import (
	"context"
	"fmt"
	"net"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

const (
	DomainRecordFinalizer = "domainrecord.core.apoxy.dev/finalizer"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type DomainRecord struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DomainRecordSpec   `json:"spec,omitempty"`
	Status DomainRecordStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &DomainRecord{}
	_ resource.Object                      = &DomainRecord{}
	_ resource.ObjectWithStatusSubResource = &DomainRecord{}
	_ rest.SingularNameProvider            = &DomainRecord{}
	_ resourcestrategy.TableConverter      = &DomainRecord{}
)

type DomainRecordSpec struct {
	// Zone is the name of the DomainZone that manages this record.
	// Optional - empty means standalone (custom domain, not zone-managed).
	// +optional
	Zone string `json:"zone,omitempty"`

	// Name is the DNS record name (e.g. "example.com", "www.example.com").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// TTL in seconds. Optional, defaults to 300.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=86400
	// +optional
	TTL *int32 `json:"ttl,omitempty"`

	// Target specifies the record data.
	// +kubebuilder:validation:Required
	Target DomainRecordTarget `json:"target"`

	// TLS configures TLS certificate provisioning for this record's domains.
	// Only valid when target.ref is set.
	// +optional
	TLS *DomainTLSSpec `json:"tls,omitempty"`
}

type DomainRecordTarget struct {
	// DNS specifies the record data directly.
	// Exactly one of DNS or Ref must be set.
	// +optional
	DNS *DomainRecordTargetDNS `json:"dns,omitempty"`

	// Ref specifies a reference to another object within Apoxy
	// (e.g. Proxy, Gateway, DomainRecord).
	// Exactly one of DNS or Ref must be set.
	// +optional
	Ref *LocalObjectReference `json:"ref,omitempty"`
}

// DomainRecordTargetDNS specifies DNS record data. Exactly one field must be populated.
// The populated field determines the DNS record type.
type DomainRecordTargetDNS struct {
	// IPs holds A/AAAA record addresses.
	// The record type (A vs AAAA) is determined by the IP address format.
	// +optional
	IPs []string `json:"ips,omitempty"`

	// FQDN holds a CNAME record target.
	// +optional
	FQDN *string `json:"fqdn,omitempty"`

	// TXT holds TXT record values.
	// +optional
	TXT []string `json:"txt,omitempty"`

	// MX holds Mail Exchange record values (e.g. "10 mail.example.com").
	// +optional
	MX []string `json:"mx,omitempty"`

	// DKIM holds DKIM (DomainKeys Identified Mail) values.
	// Values should be DKIM public key records (e.g. "v=DKIM1; k=rsa; p=...").
	// +optional
	DKIM []string `json:"dkim,omitempty"`

	// SPF holds SPF (Sender Policy Framework) values.
	// Values should follow SPF syntax (e.g. "v=spf1 include:_spf.google.com ~all").
	// +optional
	SPF []string `json:"spf,omitempty"`

	// DMARC holds DMARC values.
	// Values should follow DMARC syntax (e.g. "v=DMARC1; p=reject; rua=mailto:...").
	// +optional
	DMARC []string `json:"dmarc,omitempty"`

	// CAA holds Certification Authority Authorization record values.
	// +optional
	CAA []string `json:"caa,omitempty"`

	// SRV holds Service Locator record values.
	// +optional
	SRV []string `json:"srv,omitempty"`

	// NS holds Name Server record values.
	// +optional
	NS []string `json:"ns,omitempty"`

	// DS holds DS (Delegation Signer) records for DNSSEC chain of trust.
	// Values should be DS record data (e.g. "12345 8 2 <digest>").
	// +optional
	DS []string `json:"ds,omitempty"`

	// DNSKEY holds DNSKEY records for DNSSEC.
	// Values should be DNSKEY record data (e.g. "257 3 8 <base64-encoded-key>").
	// +optional
	DNSKEY []string `json:"dnskey,omitempty"`
}

// DNSFieldKey returns the key identifying which DNS field is populated.
// Returns empty string if no field is populated.
func (d *DomainRecordTargetDNS) DNSFieldKey() string {
	if d == nil {
		return ""
	}
	if len(d.IPs) > 0 {
		return "ips"
	}
	if d.FQDN != nil {
		return "fqdn"
	}
	if len(d.TXT) > 0 {
		return "txt"
	}
	if len(d.MX) > 0 {
		return "mx"
	}
	if len(d.DKIM) > 0 {
		return "dkim"
	}
	if len(d.SPF) > 0 {
		return "spf"
	}
	if len(d.DMARC) > 0 {
		return "dmarc"
	}
	if len(d.CAA) > 0 {
		return "caa"
	}
	if len(d.SRV) > 0 {
		return "srv"
	}
	if len(d.NS) > 0 {
		return "ns"
	}
	if len(d.DS) > 0 {
		return "ds"
	}
	if len(d.DNSKEY) > 0 {
		return "dnskey"
	}
	return ""
}

// PopulatedFieldCount returns the number of populated DNS fields.
func (d *DomainRecordTargetDNS) PopulatedFieldCount() int {
	if d == nil {
		return 0
	}
	count := 0
	if len(d.IPs) > 0 {
		count++
	}
	if d.FQDN != nil {
		count++
	}
	if len(d.TXT) > 0 {
		count++
	}
	if len(d.MX) > 0 {
		count++
	}
	if len(d.DKIM) > 0 {
		count++
	}
	if len(d.SPF) > 0 {
		count++
	}
	if len(d.DMARC) > 0 {
		count++
	}
	if len(d.CAA) > 0 {
		count++
	}
	if len(d.SRV) > 0 {
		count++
	}
	if len(d.NS) > 0 {
		count++
	}
	if len(d.DS) > 0 {
		count++
	}
	if len(d.DNSKEY) > 0 {
		count++
	}
	return count
}

type DomainRecordStatus struct {
	// Type is the resolved DNS record type (A, AAAA, CNAME, TXT, MX, etc.).
	// Derived from the populated DNS field or resolved from ref.
	// +optional
	Type string `json:"type,omitempty"`

	// Conditions contains domain record conditions.
	// Standard conditions: Ready, ZoneReady, TargetReady.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ResolvedValues contains the actual DNS values configured.
	// Populated by the controller when target.ref is used.
	// +optional
	ResolvedValues []string `json:"resolvedValues,omitempty"`
}

var _ resource.StatusSubResource = &DomainRecordStatus{}

func (s *DomainRecordStatus) SubResourceName() string {
	return "status"
}

func (s *DomainRecordStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*DomainRecord)
	if ok {
		parent.Status = *s
	}
}

func (r *DomainRecord) GetObjectMeta() *metav1.ObjectMeta {
	return &r.ObjectMeta
}

func (r *DomainRecord) NamespaceScoped() bool {
	return false
}

func (r *DomainRecord) New() runtime.Object {
	return &DomainRecord{}
}

func (r *DomainRecord) NewList() runtime.Object {
	return &DomainRecordList{}
}

func (r *DomainRecord) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "domainrecords",
	}
}

func (r *DomainRecord) IsStorageVersion() bool {
	return true
}

func (r *DomainRecord) GetSingularName() string {
	return "domainrecord"
}

func (r *DomainRecord) GetStatus() resource.StatusSubResource {
	return &r.Status
}

//+kubebuilder:object:root=true
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DomainRecordList is a list of DomainRecord resources.
type DomainRecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DomainRecord `json:"items"`
}

var (
	_ resource.ObjectList             = &DomainRecordList{}
	_ resourcestrategy.TableConverter = &DomainRecordList{}
)

func (l *DomainRecordList) GetListMeta() *metav1.ListMeta {
	return &l.ListMeta
}

// ConvertToTable implements rest.TableConvertor for DomainRecordList.
func (l *DomainRecordList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return domainRecordListToTable(l, tableOptions)
}

// ConvertToTable implements rest.TableConvertor for DomainRecord.
func (r *DomainRecord) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return domainRecordToTable(r, tableOptions)
}

// domainRecordStatusString returns a human-readable status from the Ready condition.
func domainRecordStatusString(r *DomainRecord) string {
	for _, c := range r.Status.Conditions {
		if c.Type == "Ready" {
			if c.Status == metav1.ConditionTrue {
				return "Ready"
			}
			return c.Reason
		}
	}
	return "Pending"
}

// domainRecordTargetString returns a display string for the record's target value.
func domainRecordTargetString(r *DomainRecord) string {
	if r.Spec.Target.Ref != nil {
		ref := r.Spec.Target.Ref
		return fmt.Sprintf("%s://%s", strings.ToLower(string(ref.Kind)), ref.Name)
	}
	if r.Spec.Target.DNS != nil {
		dns := r.Spec.Target.DNS
		if len(dns.IPs) > 0 {
			return formatMultiValue(dns.IPs, 40)
		}
		if dns.FQDN != nil {
			return truncateString(*dns.FQDN, 40)
		}
		if len(dns.TXT) > 0 {
			return formatMultiValue(dns.TXT, 40)
		}
		if len(dns.MX) > 0 {
			return formatMultiValue(dns.MX, 40)
		}
		if len(dns.DKIM) > 0 {
			return formatMultiValue(dns.DKIM, 40)
		}
		if len(dns.SPF) > 0 {
			return formatMultiValue(dns.SPF, 40)
		}
		if len(dns.DMARC) > 0 {
			return formatMultiValue(dns.DMARC, 40)
		}
		if len(dns.CAA) > 0 {
			return formatMultiValue(dns.CAA, 40)
		}
		if len(dns.SRV) > 0 {
			return formatMultiValue(dns.SRV, 40)
		}
		if len(dns.NS) > 0 {
			return formatMultiValue(dns.NS, 40)
		}
		if len(dns.DS) > 0 {
			return formatMultiValue(dns.DS, 40)
		}
		if len(dns.DNSKEY) > 0 {
			return formatMultiValue(dns.DNSKEY, 40)
		}
	}
	return ""
}

// domainRecordTypeString returns the DNS record type for display.
func domainRecordTypeString(r *DomainRecord) string {
	if r.Status.Type != "" {
		return r.Status.Type
	}
	if r.Spec.Target.Ref != nil {
		return "Ref"
	}
	if r.Spec.Target.DNS != nil {
		dns := r.Spec.Target.DNS
		if len(dns.IPs) > 0 {
			if ip := net.ParseIP(dns.IPs[0]); ip != nil && ip.To4() == nil {
				return "AAAA"
			}
			return "A"
		}
		if dns.FQDN != nil {
			return "CNAME"
		}
		key := dns.DNSFieldKey()
		if key != "" {
			return strings.ToUpper(key)
		}
	}
	return ""
}

// domainRecordTTL returns the effective TTL for display.
func domainRecordTTL(r *DomainRecord) int32 {
	if r.Spec.TTL != nil {
		return *r.Spec.TTL
	}
	return 300
}

func domainRecordToTable(r *DomainRecord, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}

	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = domainRecordColumnDefinitions()
	}

	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			r.Spec.Name,
			domainRecordTypeString(r),
			r.Spec.Zone,
			domainRecordTTL(r),
			domainRecordTargetString(r),
			domainRecordStatusString(r),
			formatAge(r.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: r},
	})

	table.ResourceVersion = r.ResourceVersion
	return table, nil
}

func domainRecordListToTable(list *DomainRecordList, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}

	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = domainRecordColumnDefinitions()
	}

	for i := range list.Items {
		r := &list.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				r.Spec.Name,
				domainRecordTypeString(r),
				r.Spec.Zone,
				domainRecordTTL(r),
				domainRecordTargetString(r),
				domainRecordStatusString(r),
				formatAge(r.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: r},
		})
	}

	table.ResourceVersion = list.ResourceVersion
	table.Continue = list.Continue
	table.RemainingItemCount = list.RemainingItemCount

	return table, nil
}

func domainRecordColumnDefinitions() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the domain record"},
		{Name: "Type", Type: "string", Description: "DNS record type (A, AAAA, CNAME, TXT, MX, etc.)"},
		{Name: "Zone", Type: "string", Description: "Zone the record belongs to"},
		{Name: "TTL", Type: "integer", Description: "Time-to-live in seconds"},
		{Name: "Target", Type: "string", Description: "Target value"},
		{Name: "Ready", Type: "string", Description: "Whether the record is ready"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}
