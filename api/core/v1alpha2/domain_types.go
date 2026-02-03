package v1alpha2

import (
	"context"
	"fmt"
	"strings"
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

type DomainTargetDNS struct {
	// DNSOnly is a flag to indicate if the domain represents only a DNS record
	// and no traffic is routed via Apoxy. This flag only applies to A/AAAA/CNAME records.
	// +kubebuilder:validation:Default=false
	// +optional
	DNSOnly bool `json:"dnsOnly,omitempty"`

	// IPs is the list of IP addresses of the target.
	// Setting this field will create an A/AAAA record (multi-value).
	// Cannot be set with FQDN.
	// +kubebuilder:validation:MaxItems=20
	// +optional
	IPs []string `json:"ips,omitempty"`

	// FQDN is the fully qualified domain name of the target.
	// Setting this field will create an CNAME record.
	// Cannot be set with IPs.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	FQDN *string `json:"fqdn,omitempty"`

	// TXT record value.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	TXT []string `json:"txt,omitempty"`

	// MX represents a Mail Exchange record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	MX []string `json:"mx,omitempty"`

	// DKIM represents a DomainKeys Identified Mail record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +optional
	DKIM []string `json:"dkim,omitempty"`

	// SPF represents a Sender Policy Framework record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +optional
	SPF []string `json:"spf,omitempty"`

	// DMARC represents a Domain-based Message Authentication, Reporting & Conformance record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +optional
	DMARC []string `json:"dmarc,omitempty"`

	// CAA represents a Certification Authority Authorization record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +optional
	CAA []string `json:"caa,omitempty"`

	// SRV represents a Service Locator record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +optional
	SRV []string `json:"srv,omitempty"`

	// NS represents a Name Server record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	NS []string `json:"ns,omitempty"`

	// DS represents a Delegation Signer record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +optional
	DS []string `json:"ds,omitempty"`

	// DNSKEY represents a DNS Key record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +optional
	DNSKEY []string `json:"dnskey,omitempty"`

	// TTL is the time-to-live of the domain record.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Required
	// +kubebuilder:default=20
	// +kubebuilder:validation:Format=int32
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl"`
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

// FQDNStatus represents the status of an individual FQDN managed by the Domain.
type FQDNStatus struct {
	// FQDN is the fully qualified domain name.
	FQDN string `json:"fqdn"`

	// Phase represents the current state of this FQDN.
	Phase FQDNPhase `json:"phase"`

	// Conditions contains detailed status information for this FQDN.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type DomainStatus struct {
	// Phase of the domain (aggregated from all FQDNs).
	Phase DomainPhase `json:"phase,omitempty"`

	// tFQDNStatus contains the status of each FQDN managed by this Domain.
	// +optional
	FQDNStatus []FQDNStatus `json:"fqdnStatus,omitempty"`
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

func domainToTable(domain *Domain, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}

	// Add column definitions (unless NoHeaders is set)
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the domain"},
			{Name: "Zone", Type: "string", Description: "Zone the domain is managed under"},
			{Name: "Target", Type: "string", Description: "Target type (DNS, Ref, or None)"},
			{Name: "Status", Type: "string", Description: "Current status of the domain"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}

	// Add row data
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			domain.Name,
			domain.Spec.Zone,
			getDomainTarget(domain),
			string(domain.Status.Phase),
			formatAge(domain.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: domain},
	})

	// Set resource version
	table.ResourceVersion = domain.ResourceVersion

	return table, nil
}

func domainListToTable(list *DomainList, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}

	// Add column definitions
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the domain"},
			{Name: "Zone", Type: "string", Description: "Zone the domain is managed under"},
			{Name: "Target", Type: "string", Description: "Target type (DNS, Ref, or None)"},
			{Name: "Phase", Type: "string", Description: "Current phase of the domain"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}

	// Add rows for each item
	for i := range list.Items {
		domain := &list.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				domain.Name,
				domain.Spec.Zone,
				getDomainTarget(domain),
				string(domain.Status.Phase),
				formatAge(domain.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: domain},
		})
	}

	// Set list metadata
	table.ResourceVersion = list.ResourceVersion
	table.Continue = list.Continue
	table.RemainingItemCount = list.RemainingItemCount

	return table, nil
}

// getDomainTarget returns a human-readable string describing the domain's target
func getDomainTarget(domain *Domain) string {
	if domain.Spec.Target.DNS != nil {
		dns := domain.Spec.Target.DNS
		if dns.DNSOnly {
			return "DNS-Only"
		}
		if len(dns.IPs) > 0 {
			return fmt.Sprintf("DNS(IPs:%d)", len(dns.IPs))
		}
		if dns.FQDN != nil {
			return fmt.Sprintf("DNS(CNAME:%s)", truncateString(*dns.FQDN, 20))
		}
		// Check for other DNS record types
		var recordTypes []string
		if len(dns.TXT) > 0 {
			recordTypes = append(recordTypes, "TXT")
		}
		if len(dns.MX) > 0 {
			recordTypes = append(recordTypes, "MX")
		}
		if len(dns.NS) > 0 {
			recordTypes = append(recordTypes, "NS")
		}
		if len(recordTypes) > 0 {
			return fmt.Sprintf("DNS(%s)", strings.Join(recordTypes, ","))
		}
		return "DNS"
	}
	if domain.Spec.Target.Ref != nil {
		return fmt.Sprintf("Ref(%s)", domain.Spec.Target.Ref.Name)
	}
	return "None"
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
