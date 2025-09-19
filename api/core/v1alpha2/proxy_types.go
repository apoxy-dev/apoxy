package v1alpha2

import (
	"time"

	corev1 "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

const (
	ProxyFinalizer = "proxy.core.apoxy.dev/finalizer"

	// DefaultDrainTimeout is the default duration to drain connections before terminating the proxy.
	// +kubebuilder:validation:Format=duration
	DefaultDrainTimeout = 30 * time.Second
)

// InfraProvider defines the infrastructure provider where the proxy will be deployed.
type InfraProvider string

const (
	// InfraProviderCloud is the cloud provider.
	// This provider deploys proxies within Apoxy Edge.
	InfraProviderCloud InfraProvider = "cloud"
	// InfraProviderKubernetes is the kubernetes provider.
	// This provider is used to deploy the proxy as a kubernetes pod.
	InfraProviderKubernetes InfraProvider = "kubernetes"
	// InfraProviderUnmanaged is the unmanaged provider.
	// This provider is used for proxies that are deployed by users themselves and
	// are not managed by Apoxy Control Plane.
	InfraProviderUnmanaged InfraProvider = "unmanaged"
)

type ShutdownConfig struct {
	// DrainTimeout is the amount of time to wait before terminating the proxy.
	// Defaults to 30s.
	// +optional
	DrainTimeout *metav1.Duration `json:"drainTimeout,omitempty"`

	// MinimumDrainTime is the minimum amount of time to wait before terminating the proxy.
	// This is useful for ensuring downstream loadbalancers have enough time to
	// pick up healthcheck status and drain the backend target.
	// Can not be less than DrainTimeout.
	// Defaults to 30s.
	// +optional
	MinimumDrainTime *metav1.Duration `json:"minimumDrainTime,omitempty"`
}

type ProxyAccessLogs struct {
	// If set, additional fields to add to the default Envoy access logs.
	// Envoy [command operators](https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage#command-operators)
	// can be used as values for fields. Note that attempting to override
	// default fields will not have any effect.
	JSON map[string]string `json:"json,omitempty"`

	// TODO: support additional sinks.
}

type ProxyContentLogs struct {
	// Enable request body content logging.
	RequestBodyEnabled bool `json:"requestBodyEnabled"`

	// Enable response body content logging.
	ResponseBodyEnabled bool `json:"responseBodyEnabled"`
}

type ProxyTracing struct {
	// Enable tracing.
	Enabled bool `json:"enabled"`

	// Additional tags to populate on the traces.
	Tags map[string]ProxyTracingTagValue `json:"tags,omitempty"`
}

// ProxyTracingTagValue defines a tag value to populate on the traces.
type ProxyTracingTagValue struct {
	// Value is a string value for the tag.
	// This may be set with a Header as a fallback/default value.
	Value string `json:"value"`

	// Header is a request header who's value should be set as this tag's value.
	Header string `json:"header"`
}

// ProxyTelementry defines the monitoring configuration for a Proxy.
type ProxyTelementry struct {
	// AccessLogs configures how access logs are handled.
	// Note that access logs cannot be disabled.
	AccessLogs *ProxyAccessLogs `json:"accessLogs,omitempty"`

	// ContentLogs configures how request and response body content are handled.
	// Also refered to as Taps in Envoy. Disabled by default.
	ContentLogs *ProxyContentLogs `json:"contentLogs,omitempty"`

	// Tracing configures how tracing is handled.
	// Disabled by default.
	Tracing *ProxyTracing `json:"tracing,omitempty"`

	// Custom OpenTelemetry collector configuration.
	// Only supported for unmanaged proxies.
	// This must be a ConfigMap or a Secret in the same namespace as Backplane.
	OtelCollectorConfig *corev1.LocalObjectReference `json:"otelCollectorConfig,omitempty"`

	// For enabling third party integrations.
	// This is only supported for cloud proxies.
	ThirdPartySinks *ThirdPartySinks `json:"thirdPartySinks,omitempty"`
}

type APIKey struct {
	// Key is the API key.
	Key string `json:"key,omitempty"`

	// KeyData is the base64 encoded API key.
	KeyData []byte `json:"keyData,omitempty"`
}

type ThirdPartySinks struct {
	// AxiomLogs is the API key for Axiom logs.
	AxiomLogs *APIKey `json:"axiomLogs,omitempty"`

	// AxiomTraces is the API key for Axiom traces.
	AxiomTraces *APIKey `json:"axiomTraces,omitempty"`

	// DatadogLogs is the API key for Datadog logs.
	DatadogLogs *APIKey `json:"datadogLogs,omitempty"`

	// DatadogTraces is the API key for Datadog traces.
	DatadogTraces *APIKey `json:"datadogTraces,omitempty"`

	// OpenTelemetrySink is the OpenTelemetry sink.
	OpenTelemetrySinks []OpenTelemetrySink `json:"openTelemetrySinks,omitempty"`
}

// OpenTelemetrySink defines the OpenTelemetry sink.
// This uses oltphttp
type OpenTelemetrySink struct {
	// OTLP Endpoint to send the traces to.
	Endpoint string `json:"endpoint"`

	// Headers to send with the request
	// +optional
	Headers map[string]string `json:"headers,omitempty"`

	// Compression setting
	// +optional
	Compression string `json:"compression,omitempty"`
}

// ProxySpec defines the desired specification of a Proxy.
type ProxySpec struct {
	// Provider is the infrastructure provider where the proxy will be deployed.
	// Defaults to "cloud" provider.
	Provider InfraProvider `json:"provider,omitempty"`

	// Shutdown configuration for the proxy.
	// +optional
	Shutdown *ShutdownConfig `json:"shutdown,omitempty"`

	// Telemetry configures telemetry for the Proxy.
	// +optional
	Telemetry *ProxyTelementry `json:"telemetry,omitempty"`
}

// ProxyReplicaStatus defines the status of a proxy replica.
// This is used to track the status of individual proxy replicas.
type ProxyReplicaStatus struct {
	// Name of the replica.
	Name string `json:"name"`

	// Timestamp when the replica connected to the management server.
	ConnectedAt metav1.Time `json:"connectedAt"`

	// Locality specifies the location of the replica.
	// +optional
	Locality string `json:"locality,omitempty,omitzero"`

	// Optional address assigned to the replica.
	// +optional
	Address string `json:"address,omitempty,omitzero"`

	// Optional private address assigned to the replica (used for internal platform communication).
	// +optional
	PrivateAddress string `json:"privateAddress,omitempty,omitzero"`
}

// ProxyStatus defines the observed state of Proxy.
type ProxyStatus struct {
	// Replicas are statuses of the individual proxy replicas.
	Replicas []*ProxyReplicaStatus `json:"replicas,omitempty"`
}

var _ resource.StatusSubResource = &ProxyStatus{}

func (ps *ProxyStatus) SubResourceName() string {
	return "status"
}

func (ps *ProxyStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*Proxy).Status = *ps
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Proxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProxySpec   `json:"spec,omitempty"`
	Status ProxyStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Proxy{}
	_ resource.Object                      = &Proxy{}
	_ resource.ObjectWithStatusSubResource = &Proxy{}
	_ rest.SingularNameProvider            = &Proxy{}
)

func (p *Proxy) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *Proxy) NamespaceScoped() bool {
	return false
}

func (p *Proxy) New() runtime.Object {
	return &Proxy{}
}

func (p *Proxy) NewList() runtime.Object {
	return &ProxyList{}
}

func (p *Proxy) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "proxies",
	}
}

func (p *Proxy) IsStorageVersion() bool {
	return true
}

func (p *Proxy) GetSingularName() string {
	return "proxy"
}

func (p *Proxy) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProxyList contains a list of Proxy objects.
type ProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Proxy `json:"items"`
}

var _ resource.ObjectList = &ProxyList{}

func (pl *ProxyList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
