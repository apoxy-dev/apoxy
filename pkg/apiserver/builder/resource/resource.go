// Package resource defines interfaces for API resources.
// These interfaces are compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource
// and allow API types to be registered with the API server builder.
package resource

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Object is the interface that all API resources must implement.
// This interface is compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource.Object
type Object interface {
	runtime.Object

	// GetObjectMeta returns the object's metadata.
	GetObjectMeta() *metav1.ObjectMeta

	// NamespaceScoped returns true if the resource is namespace-scoped.
	NamespaceScoped() bool

	// New returns a new instance of the resource.
	New() runtime.Object

	// NewList returns a new list instance of the resource.
	NewList() runtime.Object

	// GetGroupVersionResource returns the GroupVersionResource for this resource.
	GetGroupVersionResource() schema.GroupVersionResource

	// IsStorageVersion returns true if this version is the storage version.
	IsStorageVersion() bool
}

// ObjectWithStatusSubResource is implemented by resources that have a /status subresource.
type ObjectWithStatusSubResource interface {
	Object

	// GetStatus returns the status subresource.
	GetStatus() StatusSubResource
}

// StatusSubResource is the interface implemented by status types.
type StatusSubResource interface {
	// SubResourceName returns the name of the subresource (typically "status").
	SubResourceName() string

	// CopyTo copies the status to the parent object.
	CopyTo(parent ObjectWithStatusSubResource)
}

// ObjectList is the interface implemented by list types.
type ObjectList interface {
	runtime.Object

	// GetListMeta returns the list metadata.
	GetListMeta() *metav1.ListMeta
}

// MultiVersionObject is implemented by resources that support multiple API versions.
// This allows conversion between versions during validation and storage operations.
type MultiVersionObject interface {
	runtime.Object

	// NewStorageVersionObject returns a new instance of the storage version type.
	NewStorageVersionObject() runtime.Object

	// ConvertToStorageVersion converts this object to the storage version and
	// copies it to the given destination object.
	ConvertToStorageVersion(dst runtime.Object) error

	// ConvertFromStorageVersion converts the storage version object to this version.
	ConvertFromStorageVersion(src runtime.Object) error
}

// ObjectWithArbitrarySubResource is implemented by resources that have arbitrary subresources.
type ObjectWithArbitrarySubResource interface {
	Object

	// GetArbitrarySubResources returns the arbitrary subresources.
	GetArbitrarySubResources() []ArbitrarySubResource
}

// ArbitrarySubResource is the interface for arbitrary subresources.
type ArbitrarySubResource interface {
	// SubResourceName returns the name of the subresource.
	SubResourceName() string

	// New returns a new instance of the subresource.
	New() runtime.Object
}

// Defaulter is implemented by types that have default values.
// This interface is defined here to avoid circular imports with the rest package.
// When a type implements Defaulter, AddToScheme will register its Default() method
// with the scheme so that defaults are applied during deserialization.
type Defaulter interface {
	Default()
}

// registerConversions registers bidirectional conversion functions between
// a non-storage version type and its storage version type.
func registerConversions(s *runtime.Scheme, mv MultiVersionObject) error {
	// Get type information
	srcType := reflect.TypeOf(mv)
	storageObj := mv.NewStorageVersionObject()
	dstType := reflect.TypeOf(storageObj)

	// Create nil pointers for registration
	srcPtr := reflect.New(srcType.Elem()).Interface()
	dstPtr := reflect.New(dstType.Elem()).Interface()

	// Register conversion: non-storage -> storage
	if err := s.AddConversionFunc(srcPtr, dstPtr, func(a, b interface{}, scope conversion.Scope) error {
		src, ok := a.(MultiVersionObject)
		if !ok {
			return nil
		}
		dst, ok := b.(runtime.Object)
		if !ok {
			return nil
		}
		return src.ConvertToStorageVersion(dst)
	}); err != nil {
		return err
	}

	// Register conversion: storage -> non-storage
	// For this direction, we need to create a new instance of the non-storage type
	// and call ConvertFromStorageVersion on it
	if err := s.AddConversionFunc(dstPtr, srcPtr, func(a, b interface{}, scope conversion.Scope) error {
		src, ok := a.(runtime.Object)
		if !ok {
			return nil
		}
		dst, ok := b.(MultiVersionObject)
		if !ok {
			return nil
		}
		return dst.ConvertFromStorageVersion(src)
	}); err != nil {
		return err
	}

	return nil
}

// AddToScheme returns a function that adds the given object to a scheme.
// This is used for scheme registration during builder setup.
func AddToScheme(obj Object) func(*runtime.Scheme) error {
	return func(s *runtime.Scheme) error {
		gvr := obj.GetGroupVersionResource()
		gv := gvr.GroupVersion()

		// Register with the external version
		s.AddKnownTypes(gv, obj.New(), obj.NewList())

		// For storage version types, also register with the internal version.
		// This is required for strategic merge patch to work.
		if obj.IsStorageVersion() {
			internalGV := schema.GroupVersion{Group: gv.Group, Version: runtime.APIVersionInternal}
			s.AddKnownTypes(internalGV, obj.New(), obj.NewList())
		} else {
			// For non-storage version types that implement MultiVersionObject,
			// register conversion functions to/from the storage version.
			if mv, ok := obj.(MultiVersionObject); ok {
				if err := registerConversions(s, mv); err != nil {
					return err
				}
			}
		}

		// Register the defaulting function if the object implements Defaulter.
		// This ensures defaults are applied during deserialization, before the
		// object reaches any handler.
		if _, ok := obj.(Defaulter); ok {
			s.AddTypeDefaultingFunc(obj.New(), func(o interface{}) {
				if d, ok := o.(Defaulter); ok {
					d.Default()
				}
			})
		}

		return nil
	}
}
