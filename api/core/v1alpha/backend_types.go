package v1alpha

import (
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apirest "k8s.io/apiserver/pkg/registry/rest"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"

	v1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Backend configures a backend (upstream) endpoint for a Proxy.
type Backend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackendSpec   `json:"spec,omitempty"`
	Status BackendStatus `json:"status,omitempty"`
}

// BackendProto defines the protocol to use for the backend.
// +kubebuilder:validation:Enum="";tls;h2;h2c
type BackendProto string

const (
	// BackendProtoTLS allows requests to be forwarded to the backend over TLS.
	// Should be used for HTTP/1.1 over TLS.
	BackendProtoTLS BackendProto = "tls"

	// BackendProtoH2 allows requests to be forwarded to the backend over HTTP/2.
	// Should be used for HTTP/2 over TLS.
	BackendProtoH2 BackendProto = "h2"

	// BackendProtoH2C allows requests to be forwarded to the backend over HTTP/2 cleartext.
	BackendProtoH2C BackendProto = "h2c"
)

type BackendSpec struct {
	// List of endpoints to connect to.
	Endpoints []BackendEndpoint `json:"endpoints"`

	// Specifies whether the backend should be dynamically proxied.
	// If specified, Envoy's HTTP Dynamic Forward Proxy will be used to proxy requests to the backend.
	// See: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_proxy#arch-overview-http-dynamic-forward-proxy
	// +optional
	DynamicProxy *DynamicProxySpec `json:"dynamicProxy,omitempty"`

	// Protocol defines a protocol to use for the backend.
	Protocol BackendProto `json:"protocol"`
}

type BackendEndpoint struct {
	// FQDN is the fully qualified domain name of the endpoint.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9]))*$`
	// +optional
	FQDN string `json:"fqdn,omitempty"`

	// Endpoint defined as an IPv4/IPv6 address.
	// +kubebuilder:validation:Format=ipv4
	// +kubebuilder:validation:Format=ipv6
	// +optional
	IP string `json:"ip,omitempty"`
}

type DynamicProxySpec struct {
	DnsCacheConfig *DynamicProxyDnsCacheConfig `json:"dnsCacheConfig,omitempty"`
}

type DynamicProxyDNSLookupFamily string

const (
	// DynamicProxyDNSLookupFamilyAuto specifies that the DNS lookup family should be automatically determined.
	DynamicProxyDNSLookupFamilyAuto DynamicProxyDNSLookupFamily = "auto"
	// DynamicProxyDNSLookupFamilyV4Only specifies that the DNS lookup family should be IPv4 only.
	DynamicProxyDNSLookupFamilyV4Only DynamicProxyDNSLookupFamily = "v4_only"
	// DynamicProxyDNSLookupFamilyV6Only specifies that the DNS lookup family should be IPv6 only.
	DynamicProxyDNSLookupFamilyV6Only DynamicProxyDNSLookupFamily = "v6_only"
	// DynamicProxyDNSLookupFamilyV4Preferred specifies that the DNS lookup family should prefer IPv4.
	DynamicProxyDNSLookupFamilyV4Preferred DynamicProxyDNSLookupFamily = "v4_preferred"
	// DynamicProxyDNSLookupFamilyAll specifies that the DNS lookup family should include both IPv4 and IPv6.
	DynamicProxyDNSLookupFamilyAll DynamicProxyDNSLookupFamily = "all"
)

type DynamicProxyDnsCacheConfig struct {
	// Specifies the DNS lookup family to use for the dynamic proxy.
	// Default is "auto".
	// +kubebuilder:validation:Enum=auto;v4_only;v6_only;v4_preferred;all
	// +optional
	DNSLookupFamily DynamicProxyDNSLookupFamily `json:"dnsLookupFamily,omitempty"`

	// Specifies the refresh rate for *unresolved* DNS hosts. Once a host is resolved, the TTL from the DNS
	// response is used. If the TTL is not present, the resolved host is cached for 60s by default.
	// Must be at least 1ms, and defaults to 60s.
	// +optional
	DNSRefreshRate *metav1.Duration `json:"dnsRefreshRate,omitempty"`

	// Specifies the minimum refresh rate for DNS hosts. If a host is resolved and the TTL is less than this value, the
	// host will be refreshed at this rate.
	// Default is 5s and must be at least 1s.
	// +optional
	DNSMinRefreshRate *metav1.Duration `json:"dnsMinRefreshRate,omitempty"`

	// TTL for unused hosts. Hosts that have not been used for this duration will be removed from the cache.
	// Default is 5m.
	// +optional
	HostTTL *metav1.Duration `json:"hostTTL,omitempty"`

	// Maximum number of hosts to cache.
	// Default is 1024.
	// +optional
	MaxHosts *uint32 `json:"maxHosts,omitempty"`

	// Specifies the timeout for DNS queries.
	// Default is 5s.
	// +optional
	DNSQueryTimeout *metav1.Duration `json:"dnsQueryTimeout,omitempty"`
}

type BackendStatus struct {
	// Conditions describe the current conditions of the Backend.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &BackendStatus{}

func (ps *BackendStatus) SubResourceName() string {
	return "status"
}

func (ps *BackendStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*Backend)
	if ok {
		parent.Status = *ps
	}
}

var (
	_ runtime.Object                       = &Backend{}
	_ resource.Object                      = &Backend{}
	_ resource.ObjectWithStatusSubResource = &Backend{}
	_ apirest.SingularNameProvider            = &Backend{}
)

func (p *Backend) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *Backend) NamespaceScoped() bool {
	return false
}

func (p *Backend) New() runtime.Object {
	return &Backend{}
}

func (p *Backend) NewList() runtime.Object {
	return &BackendList{}
}

func (p *Backend) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "backends",
	}
}

func (p *Backend) IsStorageVersion() bool {
	return false
}

func (p *Backend) GetSingularName() string {
	return "backend"
}

func (p *Backend) GetStatus() resource.StatusSubResource {
	return &p.Status
}

var _ resource.MultiVersionObject = &Backend{}

func (p *Backend) NewStorageVersionObject() runtime.Object {
	return &v1alpha2.Backend{}
}

func (p *Backend) ConvertToStorageVersion(storageObj runtime.Object) error {
	obj, ok := storageObj.(*v1alpha2.Backend)
	if !ok {
		return errors.New("failed to convert to v1alpha2 Backend")
	}

	obj.ObjectMeta = *p.ObjectMeta.DeepCopy()
	obj.Spec = *convertBackendSpecFromV1Alpha1ToV1Alpha2(&p.Spec)
	obj.Status = *convertBackendStatusFromV1Alpha1ToV1Alpha2(&p.Status)

	return nil
}

func (p *Backend) ConvertFromStorageVersion(storageObj runtime.Object) error {
	obj, ok := storageObj.(*v1alpha2.Backend)
	if !ok {
		return errors.New("failed to convert from v1alpha2 Backend")
	}

	p.ObjectMeta = *obj.ObjectMeta.DeepCopy()
	p.Spec = *convertBackendSpecFromV1Alpha2ToV1Alpha1(&obj.Spec)
	p.Status = *convertBackendStatusFromV1Alpha2ToV1Alpha1(&obj.Status)

	return nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BackendList contains a list of Backend objects.
type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Backend `json:"items"`
}

var _ resource.ObjectList = &BackendList{}

func (pl *BackendList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
