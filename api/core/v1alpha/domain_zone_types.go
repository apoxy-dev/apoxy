package v1alpha

import (
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"

	v1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type DomainZone struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DomainZoneSpec `json:"spec,omitempty"`

	Status DomainZoneStatus `json:"status,omitempty"`
}

type DomainZoneSpec struct {
}

// DomainZonePhase is the phase of the domain zone.
type DomainZonePhase string

const (
	// Indicates that the domain zone is pending.
	// In order to become active, the domain owner must update the
	// nameservers with the registrar to point to the Apoxy nameservers.
	DomainZonePhasePending = "Pending"
	// Active phase of the domain zone. User can create records in the domain zone.
	DomainZonePhaseActive = "Active"
)

type DomainZoneStatus struct {
	// Phase of the domain zone.
	Phase DomainZonePhase `json:"phase,omitempty"`

	// Conditions of the domain zone.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &DomainZoneStatus{}

func (as *DomainZoneStatus) SubResourceName() string {
	return "status"
}

func (as *DomainZoneStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*DomainZone)
	if ok {
		parent.Status = *as
	}
}

var _ runtime.Object = &DomainZone{}
var _ resource.Object = &DomainZone{}
var _ resource.ObjectWithStatusSubResource = &DomainZone{}
var _ rest.SingularNameProvider = &DomainZone{}

func (a *DomainZone) GetObjectMeta() *metav1.ObjectMeta {
	return &a.ObjectMeta
}

func (a *DomainZone) NamespaceScoped() bool {
	return false
}

func (a *DomainZone) New() runtime.Object {
	return &DomainZone{}
}

func (a *DomainZone) NewList() runtime.Object {
	return &DomainZoneList{}
}

func (a *DomainZone) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "domainzones",
	}
}

func (a *DomainZone) IsStorageVersion() bool {
	return false
}

func (a *DomainZone) GetSingularName() string {
	return "domainzones"
}

func (a *DomainZone) GetStatus() resource.StatusSubResource {
	return &a.Status
}

var _ resource.MultiVersionObject = &DomainZone{}

func (a *DomainZone) NewStorageVersionObject() runtime.Object {
	return &v1alpha2.DomainZone{}
}

func (a *DomainZone) ConvertToStorageVersion(storageObj runtime.Object) error {
	obj, ok := storageObj.(*v1alpha2.DomainZone)
	if !ok {
		return errors.New("failed to convert to v1alpha2 DomainZone")
	}

	obj.ObjectMeta = *a.ObjectMeta.DeepCopy()
	obj.Spec = v1alpha2.DomainZoneSpec(a.Spec)
	obj.Status = v1alpha2.DomainZoneStatus{
		Phase:      v1alpha2.DomainZonePhase(a.Status.Phase),
		Conditions: a.Status.Conditions,
	}

	return nil
}

func (a *DomainZone) ConvertFromStorageVersion(storageObj runtime.Object) error {
	obj, ok := storageObj.(*v1alpha2.DomainZone)
	if !ok {
		return errors.New("failed to convert from v1alpha2 DomainZone")
	}

	a.ObjectMeta = *obj.ObjectMeta.DeepCopy()
	a.Spec = DomainZoneSpec(obj.Spec)
	a.Status = DomainZoneStatus{
		Phase:      DomainZonePhase(obj.Status.Phase),
		Conditions: obj.Status.Conditions,
	}

	return nil
}

//+kubebuilder:object:root=true
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DomainZoneList is a list of Domain resources.
type DomainZoneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DomainZone `json:"items"`
}

var _ resource.ObjectList = &DomainZoneList{}

func (pl *DomainZoneList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
