package v1alpha2

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
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
	_ rest.SingularNameProvider            = &Backend{}
	_ resourcestrategy.TableConverter      = &Backend{}
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
	return true
}

func (p *Backend) GetSingularName() string {
	return "backend"
}

func (p *Backend) GetStatus() resource.StatusSubResource {
	return &p.Status
}

func getBackendEndpointsSummary(endpoints []BackendEndpoint) string {
	if len(endpoints) == 0 {
		return "None"
	}
	var parts []string
	for _, ep := range endpoints {
		if ep.FQDN != "" {
			parts = append(parts, ep.FQDN)
		} else if ep.IP != "" {
			parts = append(parts, ep.IP)
		}
	}
	if len(parts) == 0 {
		return "None"
	}
	return strings.Join(parts, ",")
}

// ConvertToTable implements rest.TableConvertor for pretty printing.
func (b *Backend) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the backend"},
			{Name: "Endpoints", Type: "string", Description: "Backend endpoints"},
			{Name: "Protocol", Type: "string", Description: "Backend protocol"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	table.Rows = append(table.Rows, metav1.TableRow{
		Cells: []interface{}{
			b.Name,
			getBackendEndpointsSummary(b.Spec.Endpoints),
			fmt.Sprintf("%s", b.Spec.Protocol),
			formatAge(b.CreationTimestamp.Time),
		},
		Object: runtime.RawExtension{Object: b},
	})
	table.ResourceVersion = b.ResourceVersion
	return table, nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BackendList contains a list of Backend objects.
type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Backend `json:"items"`
}

var (
	_ resource.ObjectList             = &BackendList{}
	_ resourcestrategy.TableConverter = &BackendList{}
)

func (pl *BackendList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// ConvertToTable implements rest.TableConvertor for pretty printing.
func (bl *BackendList) ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: "Name of the backend"},
			{Name: "Endpoints", Type: "string", Description: "Backend endpoints"},
			{Name: "Protocol", Type: "string", Description: "Backend protocol"},
			{Name: "Age", Type: "string", Description: "Time since creation"},
		}
	}
	for i := range bl.Items {
		b := &bl.Items[i]
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				b.Name,
				getBackendEndpointsSummary(b.Spec.Endpoints),
				fmt.Sprintf("%s", b.Spec.Protocol),
				formatAge(b.CreationTimestamp.Time),
			},
			Object: runtime.RawExtension{Object: b},
		})
	}
	table.ResourceVersion = bl.ResourceVersion
	table.Continue = bl.Continue
	table.RemainingItemCount = bl.RemainingItemCount
	return table, nil
}
