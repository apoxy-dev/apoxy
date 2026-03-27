package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

// CompressorAlgorithm defines a compression algorithm.
// +kubebuilder:validation:Enum=gzip;brotli;zstd
type CompressorAlgorithm string

const (
	CompressorAlgorithmGzip   CompressorAlgorithm = "gzip"
	CompressorAlgorithmBrotli CompressorAlgorithm = "brotli"
	CompressorAlgorithmZstd   CompressorAlgorithm = "zstd"
)

// DefaultCompressorAlgorithms is the set of algorithms enabled when none are specified.
var DefaultCompressorAlgorithms = []CompressorAlgorithm{
	CompressorAlgorithmGzip,
	CompressorAlgorithmBrotli,
	CompressorAlgorithmZstd,
}

// DefaultCompressorMinContentLength is the default minimum response size (bytes)
// that triggers compression.
const DefaultCompressorMinContentLength uint32 = 128

// CompressorSpec configures response compression on a route.
type CompressorSpec struct {
	// Disabled disables compression on this route.
	// When true, no other fields may be set.
	// +optional
	Disabled *bool `json:"disabled,omitempty"`

	// Algorithms is the list of compression algorithms to enable.
	// When not specified, all supported algorithms (gzip, brotli, zstd)
	// are enabled.
	// +optional
	Algorithms []CompressorAlgorithm `json:"algorithms,omitempty"`

	// MinContentLength is the minimum response body size in bytes
	// that will trigger compression. Must be at least 50.
	// Defaults to 128 if not specified.
	// +optional
	// +kubebuilder:validation:Minimum=50
	MinContentLength *uint32 `json:"minContentLength,omitempty"`

	// ContentType is a list of MIME types that will trigger compression.
	// When not specified, a default set is used that covers common
	// compressible types (application/json, text/html, text/plain, etc.).
	// See https://docs.apoxy.dev/docs/guides/response-compression#default-content-types
	// for the full list.
	// +optional
	ContentType []string `json:"contentType,omitempty"`
}

// HTTPRouteFilterSpec defines the desired state of HTTPRouteFilter.
// This is a union type: exactly one field must be set.
type HTTPRouteFilterSpec struct {
	// Compressor configures response compression on the route.
	// +optional
	Compressor *CompressorSpec `json:"compressor,omitempty"`
}

// HTTPRouteFilterStatus defines the observed state of HTTPRouteFilter.
type HTTPRouteFilterStatus struct {
	// Conditions describe the current conditions of the HTTPRouteFilter.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &HTTPRouteFilterStatus{}

func (s *HTTPRouteFilterStatus) SubResourceName() string {
	return "status"
}

func (s *HTTPRouteFilterStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*HTTPRouteFilter)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HTTPRouteFilter is the Schema for the httproutefilters API.
// It defines per-route HTTP filter configuration that can be attached
// to an HTTPRoute via extensionRef.
type HTTPRouteFilter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HTTPRouteFilterSpec   `json:"spec,omitempty"`
	Status HTTPRouteFilterStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &HTTPRouteFilter{}
	_ resource.Object                      = &HTTPRouteFilter{}
	_ resource.ObjectWithStatusSubResource = &HTTPRouteFilter{}
	_ rest.SingularNameProvider            = &HTTPRouteFilter{}
)

func (h *HTTPRouteFilter) GetObjectMeta() *metav1.ObjectMeta {
	return &h.ObjectMeta
}

func (h *HTTPRouteFilter) NamespaceScoped() bool {
	return false
}

func (h *HTTPRouteFilter) New() runtime.Object {
	return &HTTPRouteFilter{}
}

func (h *HTTPRouteFilter) NewList() runtime.Object {
	return &HTTPRouteFilterList{}
}

func (h *HTTPRouteFilter) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "httproutefilters",
	}
}

func (h *HTTPRouteFilter) IsStorageVersion() bool {
	return true
}

func (h *HTTPRouteFilter) GetSingularName() string {
	return "httproutefilter"
}

func (h *HTTPRouteFilter) GetStatus() resource.StatusSubResource {
	return &h.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HTTPRouteFilterList contains a list of HTTPRouteFilter.
type HTTPRouteFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HTTPRouteFilter `json:"items"`
}

var _ resource.ObjectList = &HTTPRouteFilterList{}

func (hl *HTTPRouteFilterList) GetListMeta() *metav1.ListMeta {
	return &hl.ListMeta
}
