package resource

import (
	"fmt"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

// Object must be implemented by all resources served by the apiserver.
type Object interface {
	runtime.Object
	rest.Scoper

	GetObjectMeta() *metav1.ObjectMeta
	New() runtime.Object
	NewList() runtime.Object
	GetGroupVersionResource() schema.GroupVersionResource
	IsStorageVersion() bool
}

// ObjectList must be implemented by all resources' list object.
type ObjectList interface {
	runtime.Object
	GetListMeta() *metav1.ListMeta
}

// MultiVersionObject should be implemented if the resource is not the storage version.
type MultiVersionObject interface {
	NewStorageVersionObject() runtime.Object
	ConvertToStorageVersion(storageObj runtime.Object) error
	ConvertFromStorageVersion(storageObj runtime.Object) error
}

// ObjectWithStatusSubResource defines an interface for getting and setting the
// status sub-resource for a resource.
type ObjectWithStatusSubResource interface {
	Object
	GetStatus() StatusSubResource
}

// SubResource is the base interface for sub-resources.
type SubResource interface {
	SubResourceName() string
}

// StatusSubResource defines required methods for implementing a status subresource.
type StatusSubResource interface {
	SubResource
	CopyTo(parent ObjectWithStatusSubResource)
}

// AddToScheme returns a function to add the Objects to the scheme.
//
// It registers objects returned by New and NewList under each object's
// GroupVersion. For storage-version objects it also registers them under
// the __internal group version. For non-storage versions it registers
// conversion functions via MultiVersionObject. If the object implements
// resourcestrategy.Defaulter, a defaulting function is registered.
func AddToScheme(objs ...Object) func(s *runtime.Scheme) error {
	return func(s *runtime.Scheme) error {
		for i := range objs {
			obj := objs[i]
			s.AddKnownTypes(obj.GetGroupVersionResource().GroupVersion(), obj.New(), obj.NewList())
			if obj.IsStorageVersion() {
				s.AddKnownTypes(schema.GroupVersion{
					Group:   obj.GetGroupVersionResource().Group,
					Version: runtime.APIVersionInternal,
				}, obj.New(), obj.NewList())
			} else {
				multiVersionObj, ok := obj.(MultiVersionObject)
				if !ok {
					return fmt.Errorf("resource should implement MultiVersionObject if it's not storage-version")
				}
				storageVersionObj := multiVersionObj.NewStorageVersionObject()
				if err := s.AddConversionFunc(obj, storageVersionObj, func(from, to interface{}, _ conversion.Scope) error {
					return from.(MultiVersionObject).ConvertToStorageVersion(to.(runtime.Object))
				}); err != nil {
					return err
				}
				if err := s.AddConversionFunc(storageVersionObj, obj, func(from, to interface{}, _ conversion.Scope) error {
					return to.(MultiVersionObject).ConvertFromStorageVersion(from.(runtime.Object))
				}); err != nil {
					return err
				}
			}
			if _, ok := obj.(resourcestrategy.Defaulter); ok {
				s.AddTypeDefaultingFunc(obj, func(o interface{}) {
					o.(resourcestrategy.Defaulter).Default()
				})
			}
			if objWithStatus, ok := obj.(ObjectWithStatusSubResource); ok {
				if statusObj, ok := objWithStatus.GetStatus().(runtime.Object); ok {
					s.AddKnownTypes(obj.GetGroupVersionResource().GroupVersion(), statusObj)
				}
			}
		}
		return nil
	}
}

// DeepCopy deep-copies object from src to dst using the DeepCopyInto method.
func DeepCopy(src, dst runtime.Object) error {
	m := reflect.ValueOf(src).MethodByName("DeepCopyInto")
	if !m.IsValid() {
		return fmt.Errorf("no DeepCopyInto method found on type %v", reflect.TypeOf(src).String())
	}
	srcType := reflect.TypeOf(src)
	if m.Type().NumIn() != 1 {
		return fmt.Errorf("invalid number of arguments for DeepCopyInto upon %v, should be 1", srcType)
	}
	if !m.Type().In(0).AssignableTo(srcType) {
		return fmt.Errorf("invalid type of arguments[0] for DeepCopyInto upon %v, expected %v", srcType, srcType)
	}
	if m.Type().NumOut() != 0 {
		return fmt.Errorf("DeepCopyInto upon %v should not have return values", srcType)
	}
	m.Call([]reflect.Value{reflect.ValueOf(dst)})
	return nil
}
