package v1alpha1

import (
	"errors"

	"github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
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
//
// EdgeFunctionRevision is a single revision of an EdgeFunction
type EdgeFunctionRevision struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec EdgeFunctionSpec `json:"spec,omitempty"`

	Status EdgeFunctionRevisionStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &EdgeFunctionRevision{}
	_ resource.Object                      = &EdgeFunctionRevision{}
	_ resource.ObjectWithStatusSubResource = &EdgeFunctionRevision{}
	_ rest.SingularNameProvider            = &EdgeFunctionRevision{}
)

// GetObjectMeta implements resource.Object
func (e *EdgeFunctionRevision) GetObjectMeta() *metav1.ObjectMeta {
	return &e.ObjectMeta
}

// NamespaceScoped implements resource.Object
func (e *EdgeFunctionRevision) NamespaceScoped() bool {
	return false
}

// New implements resource.Object
func (e *EdgeFunctionRevision) New() runtime.Object {
	return &EdgeFunctionRevision{}
}

// NewList implements resource.Object
func (e *EdgeFunctionRevision) NewList() runtime.Object {
	return &EdgeFunctionRevisionList{}
}

// GetGroupVersionResource implements object.Object
func (e *EdgeFunctionRevision) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "edgefunctionrevisions",
	}
}

// IsStorageVersion implements resource.Object
func (e *EdgeFunctionRevision) IsStorageVersion() bool {
	return false
}

// GetStatus implements resource.ObjectWithStatusSubResource
func (e *EdgeFunctionRevision) GetStatus() resource.StatusSubResource {
	return &e.Status
}

// GetSingularName implements rest.SingularNameProvider
func (e *EdgeFunctionRevision) GetSingularName() string {
	return "edgefunctionrevision"
}

// EdgeFunctionRevisionStatus defines the observed state of EdgeFunctionRevision
type EdgeFunctionRevisionStatus struct {
	// Ref is the functions' uniquely identifying reference.
	Ref string `json:"ref"`

	// Conditions represent the latest available observations of an EdgeFunctionRevision's current state.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &EdgeFunctionRevisionStatus{}

func (ps *EdgeFunctionRevisionStatus) SubResourceName() string {
	return "status"
}

func (ps *EdgeFunctionRevisionStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*EdgeFunctionRevision)
	if ok {
		parent.Status = *ps
	}
}

var _ resource.MultiVersionObject = &EdgeFunctionRevision{}

func (p *EdgeFunctionRevision) NewStorageVersionObject() runtime.Object {
	return &v1alpha2.EdgeFunctionRevision{}
}

func (p *EdgeFunctionRevision) ConvertToStorageVersion(storageObj runtime.Object) error {
	obj, ok := storageObj.(*v1alpha2.EdgeFunctionRevision)
	if !ok {
		return errors.New("failed to convert to EdgeFunctionRevision")
	}

	obj.ObjectMeta = *p.ObjectMeta.DeepCopy()
	v1alpha2Spec, err := convertSpecFromV1Alpha1ToV1Alpha2(&p.Spec)
	if err != nil {
		return err
	}
	obj.Spec = *v1alpha2Spec

	obj.Status = *convertEdgeFunctionRevisionStatusFromV1Alpha1ToV1Alpha2(&p.Status)

	return nil
}

func (p *EdgeFunctionRevision) ConvertFromStorageVersion(storageObj runtime.Object) error {
	obj, ok := storageObj.(*v1alpha2.EdgeFunctionRevision)
	if !ok {
		return errors.New("failed to convert from EdgeFunctionRevision")
	}

	p.ObjectMeta = *obj.ObjectMeta.DeepCopy()
	spec, err := convertSpecFromV1Alpha2ToV1Alpha1(&obj.Spec)
	if err != nil {
		return err
	}
	p.Spec = *spec

	p.Status = *convertEdgeFunctionRevisionStatusFromV1Alpha2ToV1Alpha1(&obj.Status)

	return nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EdgeFunctionRevisionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeFunctionRevision `json:"items"`
}

var _ resource.ObjectList = &EdgeFunctionRevisionList{}

func (pl *EdgeFunctionRevisionList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
