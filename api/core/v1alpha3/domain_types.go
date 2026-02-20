package v1alpha3

import (
	"context"
	"fmt"
	"net"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

const (
	DomainFinalizer = "domain.core.apoxy.dev/finalizer"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:webhook:path=/validate-core-v1alpha-domain,mutating=false,failurePolicy=fail,sideEffects=None,groups=core.apoxy.dev,resources=domains,verbs=create;update,versions=v1alpha,name=validate.domain.apoxy.dev

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Domain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DomainSpec `json:"spec,omitempty"`

	Status DomainStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Domain{}
	_ resource.Object                      = &Domain{}
	_ resource.ObjectWithStatusSubResource = &Domain{}
	_ rest.SingularNameProvider            = &Domain{}
	_ resourcestrategy.TableConverter      = &Domain{}
)

type DomainSpec struct {
	// The zone this domain is managed under.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	Zone string `json:"zone,omitempty"`

	// The list of custom domain names to also route
	// to the target, which may be under another domain.
	// Routing may require additional verification steps.
	// +optional
	// +kubebuilder:validation:MaxItems=50
	CustomDomains []string `json:"customDomains,omitempty"`

	// Target of the domain.
	// +kubebuilder:validation:Required
	Target DomainTargetSpec `json:"target"`

	// TLS configuration for the domain.
	TLS *DomainTLSSpec `json:"tls,omitempty"`

	// Used to specify routing non-HTTP/S forwarding rules.
	// For example, forwarding tcp:10000-20000 to a specified port of a target
	// (e.g. an EdgeFunction or a TunnelEndpoint).
	// This is a Pro feature only.
	ForwardingSpec *DomainForwardingSpec `json:"forwarding,omitempty"`

	// EdgeFunction filters applied for the domain.
	Filters []*LocalObjectReference `json:"filters,omitempty"`
}

type DomainTargetSpec struct {
	// Represents targets specified via DNS.
	DNS *DomainTargetDNS `json:"dns,omitempty"`

	// Represent a target specified via a reference to another object
	// within Apoxy (e.g. Proxy, EdgeFunction (type=backend), TunnelEndpoint).
	Ref *LocalObjectReference `json:"ref,omitempty"`
}

// DNSAddressRecords holds A/AAAA record addresses with an optional per-record TTL.
type DNSAddressRecords struct {
	// Addresses is the list of IP addresses.
	// +kubebuilder:validation:MaxItems=20
	Addresses []string `json:"addresses"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSCNAMERecord holds a CNAME target with an optional per-record TTL.
type DNSCNAMERecord struct {
	// Name is the fully qualified domain name of the CNAME target.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSTXTRecords holds TXT record values with an optional per-record TTL.
type DNSTXTRecords struct {
	// Values is the list of TXT record values.
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSMXRecords holds MX record values with an optional per-record TTL.
type DNSMXRecords struct {
	// Values is the list of MX record values (e.g. "10 mail.example.com").
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSDKIMRecords holds DKIM (DomainKeys Identified Mail) values with an optional per-record TTL.
// Stored as TXT records under <selector>._domainkey.<domain>.
// Values should be DKIM public key records (e.g. "v=DKIM1; k=rsa; p=...").
type DNSDKIMRecords struct {
	// Values is the list of DKIM record values.
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSSPFRecords holds SPF (Sender Policy Framework) values with an optional per-record TTL.
// Stored as TXT records. Values should follow SPF syntax (e.g. "v=spf1 include:_spf.google.com ~all").
type DNSSPFRecords struct {
	// Values is the list of SPF record values.
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSDMARCRecords holds DMARC (Domain-based Message Authentication, Reporting & Conformance) values
// with an optional per-record TTL. Stored as TXT records under _dmarc.<domain>.
// Values should follow DMARC syntax (e.g. "v=DMARC1; p=reject; rua=mailto:...").
type DNSDMARCRecords struct {
	// Values is the list of DMARC record values.
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSCAARecords holds CAA record values with an optional per-record TTL.
type DNSCAARecords struct {
	// Values is the list of CAA record values.
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSSRVRecords holds SRV record values with an optional per-record TTL.
type DNSSRVRecords struct {
	// Values is the list of SRV record values.
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSNSRecords holds NS record values with an optional per-record TTL.
type DNSNSRecords struct {
	// Nameservers is the list of nameserver values.
	// +kubebuilder:validation:MinItems=1
	Nameservers []string `json:"nameservers"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSDSRecords holds DS (Delegation Signer) records for DNSSEC chain of trust,
// with an optional per-record TTL. Values should be DS record data (e.g. "12345 8 2 <digest>").
type DNSDSRecords struct {
	// Values is the list of DS record values.
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// DNSDNSKEYRecords holds DNSKEY records for DNSSEC, with an optional per-record TTL.
// Values should be DNSKEY record data (e.g. "257 3 8 <base64-encoded-key>").
type DNSDNSKEYRecords struct {
	// Values is the list of DNSKEY record values.
	// +kubebuilder:validation:MinItems=1
	Values []string `json:"values"`

	// TTL is the time-to-live for this record type.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

type DomainTargetDNS struct {
	// IPs holds A/AAAA record addresses.
	// Cannot be set with FQDN.
	// +optional
	IPs *DNSAddressRecords `json:"ips,omitempty"`

	// FQDN holds a CNAME record target.
	// Cannot be set with IPs.
	// +optional
	FQDN *DNSCNAMERecord `json:"fqdn,omitempty"`

	// TXT holds TXT record values.
	// +optional
	TXT *DNSTXTRecords `json:"txt,omitempty"`

	// MX holds Mail Exchange record values.
	// +optional
	MX *DNSMXRecords `json:"mx,omitempty"`

	// DKIM holds DKIM (DomainKeys Identified Mail) values.
	// Stored as TXT records under <selector>._domainkey.<domain>.
	// Values should be DKIM public key records (e.g. "v=DKIM1; k=rsa; p=...").
	// +optional
	DKIM *DNSDKIMRecords `json:"dkim,omitempty"`

	// SPF holds SPF (Sender Policy Framework) values.
	// Stored as TXT records. Values should follow SPF syntax (e.g. "v=spf1 include:_spf.google.com ~all").
	// +optional
	SPF *DNSSPFRecords `json:"spf,omitempty"`

	// DMARC holds DMARC (Domain-based Message Authentication, Reporting & Conformance) values.
	// Stored as TXT records under _dmarc.<domain>.
	// Values should follow DMARC syntax (e.g. "v=DMARC1; p=reject; rua=mailto:...").
	// +optional
	DMARC *DNSDMARCRecords `json:"dmarc,omitempty"`

	// CAA holds Certification Authority Authorization record values.
	// +optional
	CAA *DNSCAARecords `json:"caa,omitempty"`

	// SRV holds Service Locator record values.
	// +optional
	SRV *DNSSRVRecords `json:"srv,omitempty"`

	// NS holds Name Server record values.
	// +optional
	NS *DNSNSRecords `json:"ns,omitempty"`

	// DS holds DS (Delegation Signer) records for DNSSEC chain of trust.
	// Values should be DS record data (e.g. "12345 8 2 <digest>").
	// +optional
	DS *DNSDSRecords `json:"ds,omitempty"`

	// DNSKEY holds DNSKEY records for DNSSEC.
	// Values should be DNSKEY record data (e.g. "257 3 8 <base64-encoded-key>").
	// +optional
	DNSKEY *DNSDNSKEYRecords `json:"dnskey,omitempty"`
}

type DomainTLSSpec struct {
	// The Certificate Authority used to issue the TLS certificate.
	// Currently supports "letsencrypt".
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`
}

type ProtocolType string

const (
	ProtocolHTTP ProtocolType = "HTTP"
	ProtocolTLS  ProtocolType = "TLS"
	ProtocolTCP  ProtocolType = "TCP"
	ProtocolUDP  ProtocolType = "UDP"
)

type PortRange struct {
	// StartPort is the starting port of the range.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	StartPort int32 `json:"startPort"`

	// EndPort is the ending port of the range.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	EndPort int32 `json:"endPort"`
}

type ForwardingRule struct {
	// Protocol specifies the protocol for forwarding.
	// +kubebuilder:validation:Required
	Protocol ProtocolType `json:"protocol"`

	// PortRanges specifies the port ranges for forwarding.
	// +kubebuilder:validation:Required
	PortRanges []PortRange `json:"portRanges"`

	// If not specified, the connections will be forwarded to the same port it
	// was received on.
	TargetPort *int32 `json:"targetPort,omitempty"`
}

type DomainForwardingSpec struct {
	// ForwardingRules is the list of forwarding rules.
	ForwardingRules []ForwardingRule `json:"forwardingRules,omitempty"`
}

// DomainPhase is the phase of the domain.
type DomainPhase string

const (
	// DomainPhasePending is the pending phase of the domain.
	// This is the initial phase of the domain.
	DomainPhasePending = "Pending"
	DomainPhaseActive  = "Active"
	DomainPhaseError   = "Errored"
)

// FQDNPhase represents the provisioning state of an individual FQDN.
type FQDNPhase string

const (
	// FQDNPhaseWaitingForZone indicates the referenced Zone is not ready.
	FQDNPhaseWaitingForZone FQDNPhase = "WaitingForZone"
	// FQDNPhaseWaitingForDNS indicates DNS records are being created or verified.
	FQDNPhaseWaitingForDNS FQDNPhase = "WaitingForDNS"
	// FQDNPhaseActive indicates the FQDN is fully operational.
	FQDNPhaseActive FQDNPhase = "Active"
	// FQDNPhaseError indicates provisioning or validation has failed.
	FQDNPhaseError FQDNPhase = "Error"
)

// DNSRecordSource indicates the origin of a DNS record.
type DNSRecordSource string

const (
	// DNSRecordSourceSpec indicates the record comes from spec.target.dns.
	DNSRecordSourceSpec DNSRecordSource = "spec"
	// DNSRecordSourceRef indicates the record was resolved from spec.target.ref.
	DNSRecordSourceRef DNSRecordSource = "ref"
	// DNSRecordSourceSystem indicates the record was auto-generated (e.g. CNAME-only mode).
	DNSRecordSourceSystem DNSRecordSource = "system"
)

// DNSRecordStatus represents the status of an individual DNS record managed by a Domain.
type DNSRecordStatus struct {
	// Name is the DNS record name. For zone-managed domains this is relative to the
	// zone (e.g. "@", "_dmarc", "www"). For CNAME-only domains this is the full FQDN
	// (e.g. "api.example.com").
	Name string `json:"name"`
	// Type is the DNS record type ("A", "AAAA", "TXT", "MX", etc.).
	Type string `json:"type"`
	// Source indicates where this record comes from.
	Source DNSRecordSource `json:"source"`
	// Ready indicates whether this record has been created and verified.
	Ready bool `json:"ready"`
	// Message provides human-readable detail.
	// +optional
	Message string `json:"message,omitempty"`
}

type DomainStatus struct {
	// Conditions contains aggregate domain-level conditions.
	// Standard conditions: Ready, ZoneReady, DNSConfigured, CNAMEConfigured,
	// TLSReady, TargetReady, ForwardingReady.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Records contains per-record-type status for DNS records managed by this Domain.
	// +optional
	Records []DNSRecordStatus `json:"records,omitempty"`
}

var _ resource.StatusSubResource = &DomainStatus{}

func (as *DomainStatus) SubResourceName() string {
	return "status"
}

func (as *DomainStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*Domain)
	if ok {
		parent.Status = *as
	}
}

func (a *Domain) GetObjectMeta() *metav1.ObjectMeta {
	return &a.ObjectMeta
}

func (a *Domain) NamespaceScoped() bool {
	return false
}

func (a *Domain) New() runtime.Object {
	return &Domain{}
}

func (a *Domain) NewList() runtime.Object {
	return &DomainList{}
}

func (a *Domain) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "domains",
	}
}

func (a *Domain) IsStorageVersion() bool {
	return true
}

func (a *Domain) GetSingularName() string {
	return "domain"
}

func (a *Domain) GetStatus() resource.StatusSubResource {
	return &a.Status
}

//+kubebuilder:object:root=true
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DomainList is a list of Domain resources.
type DomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Domain `json:"items"`
}

var (
	_ resource.ObjectList             = &DomainList{}
	_ resourcestrategy.TableConverter = &DomainList{}
)

func (pl *DomainList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (dl *DomainList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return domainListToTable(dl, tableOptions)
}

// ConvertToTable implements rest.TableConvertor that handles table pretty printing.
func (d *Domain) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	return domainToTable(d, tableOptions)
}

// domainStatusString returns a human-readable status string from the Ready condition.
func domainStatusString(domain *Domain) string {
	for _, c := range domain.Status.Conditions {
		if c.Type == "Ready" {
			if c.Status == metav1.ConditionTrue {
				return "Ready"
			}
			return c.Reason
		}
	}
	return "Pending"
}

func domainToTable(domain *Domain, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}

	// Add column definitions (unless NoHeaders is set)
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = domainColumnDefinitions()
	}

	// Add row data — one row per record type
	rows := getDomainRows(domain)
	for i, r := range rows {
		row := metav1.TableRow{
			Cells: []interface{}{
				"", "", r.typ, r.value, r.ttl, "", "",
			},
		}
		if i == 0 {
			row.Cells[0] = domain.Name
			row.Cells[1] = domain.Spec.Zone
			row.Cells[5] = domainStatusString(domain)
			row.Cells[6] = formatAge(domain.CreationTimestamp.Time)
			row.Object = runtime.RawExtension{Object: domain}
		}
		table.Rows = append(table.Rows, row)
	}

	// Set resource version
	table.ResourceVersion = domain.ResourceVersion

	return table, nil
}

func domainListToTable(list *DomainList, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}

	// Add column definitions
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = domainColumnDefinitions()
	}

	// Add rows for each item — one row per record type
	for i := range list.Items {
		domain := &list.Items[i]
		rows := getDomainRows(domain)
		for j, r := range rows {
			row := metav1.TableRow{
				Cells: []interface{}{
					"", "", r.typ, r.value, r.ttl, "", "",
				},
			}
			if j == 0 {
				row.Cells[0] = domain.Name
				row.Cells[1] = domain.Spec.Zone
				row.Cells[5] = domainStatusString(domain)
				row.Cells[6] = formatAge(domain.CreationTimestamp.Time)
				row.Object = runtime.RawExtension{Object: domain}
			}
			table.Rows = append(table.Rows, row)
		}
	}

	// Set list metadata
	table.ResourceVersion = list.ResourceVersion
	table.Continue = list.Continue
	table.RemainingItemCount = list.RemainingItemCount

	return table, nil
}

func domainColumnDefinitions() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: "Name of the domain"},
		{Name: "Zone", Type: "string", Description: "Zone the domain is managed under"},
		{Name: "Type", Type: "string", Description: "Record type (Ref, DNS:A, DNS:AAAA, DNS:CNAME, etc.)"},
		{Name: "Value", Type: "string", Description: "Target value"},
		{Name: "TTL", Type: "integer", Description: "Time-to-live in seconds"},
		{Name: "Status", Type: "string", Description: "Current status of the domain"},
		{Name: "Age", Type: "string", Description: "Time since creation"},
	}
}

// domainRow represents a single display row for a domain record type.
type domainRow struct {
	typ   string
	value string
	ttl   int32
}

// resolveTTL returns the per-record TTL if set, otherwise 0.
func resolveTTL(ttl *int32) int32 {
	if ttl != nil {
		return *ttl
	}
	return 0
}

// getDomainRows returns one row per record type for display in a table.
// Multi-value fields are collapsed using (+N) notation.
func getDomainRows(domain *Domain) []domainRow {
	var rows []domainRow

	if domain.Spec.Target.Ref != nil {
		ref := domain.Spec.Target.Ref
		scheme := string(ref.Kind)
		switch ref.Kind {
		case "Gateway":
			scheme = "gateway"
		case "Tunnel", "TunnelNode":
			scheme = "tunnel"
		case "EdgeFunction":
			scheme = "func"
		}
		rows = append(rows, domainRow{
			typ:   "Ref",
			value: fmt.Sprintf("%s://%s", scheme, ref.Name),
			ttl:   10,
		})
	}

	if domain.Spec.Target.DNS != nil {
		dns := domain.Spec.Target.DNS

		if dns.IPs != nil && len(dns.IPs.Addresses) > 0 {
			first := dns.IPs.Addresses[0]
			recType := "A"
			if ip := net.ParseIP(first); ip != nil && ip.To4() == nil {
				recType = "AAAA"
			}
			rows = append(rows, domainRow{
				typ:   "DNS:" + recType,
				value: formatMultiValue(dns.IPs.Addresses, 30),
				ttl:   resolveTTL(dns.IPs.TTL),
			})
		}
		if dns.FQDN != nil {
			rows = append(rows, domainRow{
				typ:   "DNS:CNAME",
				value: truncateString(dns.FQDN.Name, 30),
				ttl:   resolveTTL(dns.FQDN.TTL),
			})
		}
		if dns.TXT != nil && len(dns.TXT.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:TXT",
				value: formatMultiValue(dns.TXT.Values, 30),
				ttl:   resolveTTL(dns.TXT.TTL),
			})
		}
		if dns.MX != nil && len(dns.MX.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:MX",
				value: formatMultiValue(dns.MX.Values, 30),
				ttl:   resolveTTL(dns.MX.TTL),
			})
		}
		if dns.NS != nil && len(dns.NS.Nameservers) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:NS",
				value: formatMultiValue(dns.NS.Nameservers, 30),
				ttl:   resolveTTL(dns.NS.TTL),
			})
		}
		if dns.SRV != nil && len(dns.SRV.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:SRV",
				value: formatMultiValue(dns.SRV.Values, 30),
				ttl:   resolveTTL(dns.SRV.TTL),
			})
		}
		if dns.CAA != nil && len(dns.CAA.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:CAA",
				value: formatMultiValue(dns.CAA.Values, 30),
				ttl:   resolveTTL(dns.CAA.TTL),
			})
		}
		if dns.DKIM != nil && len(dns.DKIM.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:DKIM",
				value: formatMultiValue(dns.DKIM.Values, 30),
				ttl:   resolveTTL(dns.DKIM.TTL),
			})
		}
		if dns.SPF != nil && len(dns.SPF.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:SPF",
				value: formatMultiValue(dns.SPF.Values, 30),
				ttl:   resolveTTL(dns.SPF.TTL),
			})
		}
		if dns.DMARC != nil && len(dns.DMARC.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:DMARC",
				value: formatMultiValue(dns.DMARC.Values, 30),
				ttl:   resolveTTL(dns.DMARC.TTL),
			})
		}
		if dns.DS != nil && len(dns.DS.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:DS",
				value: formatMultiValue(dns.DS.Values, 30),
				ttl:   resolveTTL(dns.DS.TTL),
			})
		}
		if dns.DNSKEY != nil && len(dns.DNSKEY.Values) > 0 {
			rows = append(rows, domainRow{
				typ:   "DNS:DNSKEY",
				value: formatMultiValue(dns.DNSKEY.Values, 30),
				ttl:   resolveTTL(dns.DNSKEY.TTL),
			})
		}
	}

	if len(rows) == 0 {
		return []domainRow{{typ: "—"}}
	}
	return rows
}

// formatMultiValue formats a slice of values as "first (+N)" with truncation.
func formatMultiValue(values []string, maxLen int) string {
	if len(values) == 0 {
		return ""
	}
	v := truncateString(values[0], maxLen)
	if n := len(values) - 1; n > 0 {
		v += fmt.Sprintf(" (+%d)", n)
	}
	return v
}

// truncateString truncates a string to maxLen characters, adding "..." if truncated
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// formatAge formats a time as a Kubernetes-style age string (e.g., "5m", "2h", "7d")
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "<unknown>"
	}
	return duration.ShortHumanDuration(time.Since(t))
}
