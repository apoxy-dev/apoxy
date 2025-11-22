package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TLSRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1alpha2.TLSRouteSpec `json:"spec,omitempty"`

	Status TLSRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &TLSRoute{}
	_ resource.Object                      = &TLSRoute{}
	_ resource.ObjectWithStatusSubResource = &TLSRoute{}
	_ rest.SingularNameProvider            = &TLSRoute{}
)

func (p *TLSRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TLSRoute) NamespaceScoped() bool {
	return false
}

func (p *TLSRoute) New() runtime.Object {
	return &TLSRoute{}
}

func (p *TLSRoute) NewList() runtime.Object {
	return &TLSRouteList{}
}

func (p *TLSRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tlsroutes",
	}
}

func (p *TLSRoute) IsStorageVersion() bool {
	return true
}

func (p *TLSRoute) GetSingularName() string {
	return "tlsroute"
}

func (p *TLSRoute) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type TLSRouteStatus struct {
	gwapiv1alpha2.TLSRouteStatus
}

var _ resource.StatusSubResource = &TLSRouteStatus{}

func (s *TLSRouteStatus) SubResourceName() string {
	return "status"
}

func (s *TLSRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*TLSRoute)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TLSRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSRoute `json:"items"`
}

var _ resource.ObjectList = &TLSRouteList{}

func (pl *TLSRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TCPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1alpha2.TCPRouteSpec `json:"spec,omitempty"`

	Status TCPRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &TCPRoute{}
	_ resource.Object                      = &TCPRoute{}
	_ resource.ObjectWithStatusSubResource = &TCPRoute{}
	_ rest.SingularNameProvider            = &TCPRoute{}
)

func (p *TCPRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TCPRoute) NamespaceScoped() bool {
	return false
}

func (p *TCPRoute) New() runtime.Object {
	return &TCPRoute{}
}

func (p *TCPRoute) NewList() runtime.Object {
	return &TCPRouteList{}
}

func (p *TCPRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tcproutes",
	}
}

func (p *TCPRoute) IsStorageVersion() bool {
	return true
}

func (p *TCPRoute) GetSingularName() string {
	return "tcproute"
}

func (p *TCPRoute) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type TCPRouteStatus struct {
	gwapiv1alpha2.TCPRouteStatus
}

var _ resource.StatusSubResource = &TCPRouteStatus{}

func (s *TCPRouteStatus) SubResourceName() string {
	return "status"
}

func (s *TCPRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*TCPRoute)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TCPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TCPRoute `json:"items"`
}

var _ resource.ObjectList = &TCPRouteList{}

func (pl *TCPRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type UDPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1alpha2.UDPRouteSpec `json:"spec,omitempty"`

	Status UDPRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &UDPRoute{}
	_ resource.Object                      = &UDPRoute{}
	_ resource.ObjectWithStatusSubResource = &UDPRoute{}
	_ rest.SingularNameProvider            = &UDPRoute{}
)

func (p *UDPRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *UDPRoute) NamespaceScoped() bool {
	return false
}

func (p *UDPRoute) New() runtime.Object {
	return &UDPRoute{}
}

func (p *UDPRoute) NewList() runtime.Object {
	return &UDPRouteList{}
}

func (p *UDPRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "udproutes",
	}
}

func (p *UDPRoute) IsStorageVersion() bool {
	return true
}

func (p *UDPRoute) GetSingularName() string {
	return "udproute"
}

func (p *UDPRoute) GetStatus() resource.StatusSubResource {
	return &p.Status
}

type UDPRouteStatus struct {
	gwapiv1alpha2.UDPRouteStatus
}

var _ resource.StatusSubResource = &UDPRouteStatus{}

func (s *UDPRouteStatus) SubResourceName() string {
	return "status"
}

func (s *UDPRouteStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*UDPRoute)
	if ok {
		parent.Status = *s
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type UDPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UDPRoute `json:"items"`
}

var _ resource.ObjectList = &UDPRouteList{}

func (pl *UDPRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
