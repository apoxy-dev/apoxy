package rest

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	apirest "k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"

	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
)

// StaticStorageProvider wraps a pre-created storage and returns it directly.
// This is used when storage is already created (e.g., SQLite REST storage).
type StaticStorageProvider struct {
	Storage apirest.Storage
}

// ResourceStorage implements StorageProvider by returning the wrapped storage.
func (p *StaticStorageProvider) ResourceStorage(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (apirest.Storage, error) {
	return p.Storage, nil
}

// NewStaticStorageProvider creates a StorageProvider that returns a pre-created storage.
func NewStaticStorageProvider(storage apirest.Storage) StorageProvider {
	return &StaticStorageProvider{Storage: storage}
}

// StoreFn is a callback to configure the genericregistry.Store during setup.
// This is compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/rest.StoreFn.
// It's used by storage backends (like kine) to configure REST options.
type StoreFn func(scheme *runtime.Scheme, store *genericregistry.Store, options *generic.StoreOptions)

// StorageProvider provides REST storage for a resource.
type StorageProvider interface {
	// ResourceStorage returns the REST storage for the resource.
	ResourceStorage(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (apirest.Storage, error)
}

// ObjectAwareStorageProvider is implemented by storage providers that have access
// to the resource object. This is used to check for subresource support.
type ObjectAwareStorageProvider interface {
	StorageProvider
	GetObject() resource.Object
}

// StorageProviderFunc is a function that returns REST storage for a resource.
type StorageProviderFunc func(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (apirest.Storage, error)

// ResourceStorage implements StorageProvider.
func (f StorageProviderFunc) ResourceStorage(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (apirest.Storage, error) {
	return f(scheme, optsGetter)
}

// storageProviderWithFn wraps a StoreFn into a StorageProvider.
type storageProviderWithFn struct {
	obj     resource.Object
	storeFn StoreFn
}

// NewStorageProviderWithFn creates a StorageProvider from an Object and StoreFn.
func NewStorageProviderWithFn(obj resource.Object, storeFn StoreFn) StorageProvider {
	return &storageProviderWithFn{obj: obj, storeFn: storeFn}
}

// GetObject returns the underlying resource object.
func (p *storageProviderWithFn) GetObject() resource.Object {
	return p.obj
}

// ResourceStorage implements StorageProvider by creating a genericregistry.Store
// and configuring it using the StoreFn callback.
func (p *storageProviderWithFn) ResourceStorage(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (apirest.Storage, error) {
	strategy := NewDefaultStrategy(p.obj, scheme)

	gvr := p.obj.GetGroupVersionResource()
	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return p.obj.New() },
		NewListFunc:               func() runtime.Object { return p.obj.NewList() },
		PredicateFunc:             MatchFunc,
		DefaultQualifiedResource:  gvr.GroupResource(),
		SingularQualifiedResource: gvr.GroupResource(),
		StorageVersioner:          schema.GroupVersions{gvr.GroupVersion()},

		CreateStrategy:      strategy,
		UpdateStrategy:      strategy,
		DeleteStrategy:      strategy,
		TableConvertor:      strategy,
		ResetFieldsStrategy: strategy,
	}

	options := &generic.StoreOptions{
		RESTOptions: optsGetter,
	}

	// Apply the StoreFn callback (e.g., to configure kine storage)
	if p.storeFn != nil {
		p.storeFn(scheme, store, options)
	}

	if err := store.CompleteWithOptions(options); err != nil {
		return nil, err
	}

	return store, nil
}

// StatusStorageProvider wraps a main storage provider to provide status subresource storage.
type StatusStorageProvider struct {
	MainStorage apirest.Storage
	Obj         resource.ObjectWithStatusSubResource
}

// ResourceStorage returns the status subresource storage.
func (s *StatusStorageProvider) ResourceStorage(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (apirest.Storage, error) {
	return &StatusREST{Store: s.MainStorage.(*genericregistry.Store), Obj: s.Obj}, nil
}

// StatusREST implements the REST endpoint for status subresources.
type StatusREST struct {
	Store *genericregistry.Store
	Obj   resource.ObjectWithStatusSubResource
}

// New returns a new instance of the parent object (for decoding updates).
// We return the parent object because status types don't implement runtime.Object
// (they lack DeepCopyObject). The Update method receives the full parent object
// and extracts the status from it.
func (r *StatusREST) New() runtime.Object {
	return r.Obj.New()
}

// Destroy cleans up resources.
func (r *StatusREST) Destroy() {}

// Get retrieves the status of the object.
func (r *StatusREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.Store.Get(ctx, name, options)
}

// Update updates the status of the object.
func (r *StatusREST) Update(ctx context.Context, name string, objInfo apirest.UpdatedObjectInfo, createValidation apirest.ValidateObjectFunc, updateValidation apirest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	return r.Store.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
}

// GetResetFields implements rest.ResetFieldsStrategy.
func (r *StatusREST) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	return nil
}

// Ensure StatusREST implements required interfaces.
var (
	_ apirest.Getter  = &StatusREST{}
	_ apirest.Updater = &StatusREST{}
)

// Ensure storageProviderWithFn implements ObjectAwareStorageProvider.
var _ ObjectAwareStorageProvider = &storageProviderWithFn{}
