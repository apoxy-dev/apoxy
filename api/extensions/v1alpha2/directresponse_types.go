package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

// BodyType defines how the response body is specified.
// +kubebuilder:validation:Enum=Inline
type BodyType string

const (
	// BodyTypeInline indicates the body is specified inline as a string.
	BodyTypeInline BodyType = "Inline"
)

// CustomResponseBody defines the body of the direct response.
type CustomResponseBody struct {
	// Type specifies how the body is provided.
	// Currently only "Inline" is supported.
	// +kubebuilder:validation:Required
	Type BodyType `json:"type"`

	// Inline is the literal body content when Type is "Inline".
	// +optional
	Inline *string `json:"inline,omitempty"`
}

// Header defines a custom HTTP header to include in the response.
type Header struct {
	// Name is the header name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Value is the header value.
	// +kubebuilder:validation:Required
	Value string `json:"value"`
}

// DirectResponseSpec defines the desired state of DirectResponse.
type DirectResponseSpec struct {
	// StatusCode is the HTTP status code to return.
	// Defaults to 200 if not specified.
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=599
	// +kubebuilder:default=200
	// +optional
	StatusCode *int32 `json:"statusCode,omitempty"`

	// ContentType is the Content-Type header value.
	// Defaults to "text/plain" if not specified.
	// +kubebuilder:default="text/plain"
	// +optional
	ContentType *string `json:"contentType,omitempty"`

	// Headers are additional HTTP headers to include in the response.
	// +optional
	Headers []Header `json:"headers,omitempty"`

	// Body is the response body configuration.
	// +optional
	Body *CustomResponseBody `json:"body,omitempty"`
}

// DirectResponseStatus defines the observed state of DirectResponse.
type DirectResponseStatus struct {
	// Conditions describe the current conditions of the DirectResponse.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &DirectResponseStatus{}

func (s *DirectResponseStatus) SubResourceName() string {
	return "status"
}

func (s *DirectResponseStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*DirectResponse)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DirectResponse is the Schema for the directresponses API.
// It defines a static response that can be returned by an HTTPRoute
// instead of forwarding to a backend.
type DirectResponse struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DirectResponseSpec   `json:"spec,omitempty"`
	Status DirectResponseStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &DirectResponse{}
	_ resource.Object                      = &DirectResponse{}
	_ resource.ObjectWithStatusSubResource = &DirectResponse{}
	_ rest.SingularNameProvider            = &DirectResponse{}
)

func (d *DirectResponse) GetObjectMeta() *metav1.ObjectMeta {
	return &d.ObjectMeta
}

func (d *DirectResponse) NamespaceScoped() bool {
	return false
}

func (d *DirectResponse) New() runtime.Object {
	return &DirectResponse{}
}

func (d *DirectResponse) NewList() runtime.Object {
	return &DirectResponseList{}
}

func (d *DirectResponse) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "directresponses",
	}
}

func (d *DirectResponse) IsStorageVersion() bool {
	return true
}

func (d *DirectResponse) GetSingularName() string {
	return "directresponse"
}

func (d *DirectResponse) GetStatus() resource.StatusSubResource {
	return &d.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DirectResponseList contains a list of DirectResponse.
type DirectResponseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DirectResponse `json:"items"`
}

var _ resource.ObjectList = &DirectResponseList{}

func (dl *DirectResponseList) GetListMeta() *metav1.ListMeta {
	return &dl.ListMeta
}
