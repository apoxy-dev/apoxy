package v1

import (
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=true
// +kubebuilder:object:root=true

// Lease is a wrapper around the standard coordination.k8s.io/v1 Lease that
// implements the apiserver-runtime resource.Object interface. It reuses the
// upstream LeaseSpec so clients can use the standard coordination API.
type Lease struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec coordinationv1.LeaseSpec `json:"spec,omitempty"`
}

// Implement resource.Object interface for apiserver-runtime.
var _ resource.Object = &Lease{}

func (l *Lease) GetObjectMeta() *metav1.ObjectMeta {
	return &l.ObjectMeta
}

func (l *Lease) NamespaceScoped() bool {
	return true
}

func (l *Lease) New() runtime.Object {
	return &Lease{}
}

func (l *Lease) NewList() runtime.Object {
	return &LeaseList{}
}

func (l *Lease) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "leases",
	}
}

func (l *Lease) IsStorageVersion() bool {
	return true
}

func (l *Lease) GetSingularName() string {
	return "lease"
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// LeaseList contains a list of Lease objects.
type LeaseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Lease `json:"items"`
}

var _ resource.ObjectList = &LeaseList{}

func (ll *LeaseList) GetListMeta() *metav1.ListMeta {
	return &ll.ListMeta
}
