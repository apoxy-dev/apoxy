package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Tunnel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TunnelSpec   `json:"spec,omitempty"`
	Status TunnelStatus `json:"status,omitempty"`
}

type TunnelSpec struct {
}

type TunnelStatus struct {
}

var _ resource.StatusSubResource = &TunnelStatus{}

func (ps *TunnelStatus) SubResourceName() string {
	return "status"
}

func (ps *TunnelStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*Tunnel).Status = *ps
}

var (
	_ runtime.Object                       = &Tunnel{}
	_ resource.Object                      = &Tunnel{}
	_ resource.ObjectWithStatusSubResource = &Tunnel{}
	_ rest.SingularNameProvider            = &Tunnel{}
)

func (p *Tunnel) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *Tunnel) NamespaceScoped() bool {
	return false
}

func (p *Tunnel) New() runtime.Object {
	return &Tunnel{}
}

func (p *Tunnel) NewList() runtime.Object {
	return &TunnelList{}
}

func (p *Tunnel) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "Tunnels",
	}
}

func (p *Tunnel) IsStorageVersion() bool {
	return true
}

func (p *Tunnel) GetSingularName() string {
	return "Tunnel"
}

func (p *Tunnel) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelList contains a list of Tunnel objects.
type TunnelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tunnel `json:"items"`
}

var _ resource.ObjectList = &TunnelList{}

func (pl *TunnelList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
