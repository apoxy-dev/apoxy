package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
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

type DomainSpec struct {
	// The zone this domain is managed under.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	Zone string `json:"zone,omitempty"`

	// The list of subdomains nested under the domain.
	// Allows for wildcard subdomains.
	// +kubebuilder:validation:MaxItems=50
	Subdomains []string `json:"subdomains,omitempty"`

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

type DomainStatus struct {
	// Phase of the domain.
	Phase DomainPhase `json:"phase,omitempty"`

	// Conditions recorded for the domain.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
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

var _ runtime.Object = &Domain{}
var _ resource.Object = &Domain{}
var _ resource.ObjectWithStatusSubResource = &Domain{}
var _ rest.SingularNameProvider = &Domain{}

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

var _ resource.ObjectList = &DomainList{}

func (pl *DomainList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
