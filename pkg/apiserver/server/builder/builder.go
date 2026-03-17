package builder

import (
	"context"
	"fmt"
	"strings"
	"sync"

	serverapiserver "github.com/apoxy-dev/apoxy/pkg/apiserver/server/apiserver"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/server/start"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	registryrest "k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/storage/names"
	openapicommon "k8s.io/kube-openapi/pkg/common"
	builderresource "sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
	builderutil "sigs.k8s.io/apiserver-runtime/pkg/builder/resource/util"
)

type ServerOptions = start.ServerOptions
type StoreFn func(*runtime.Scheme, *genericregistry.Store, *generic.StoreOptions)

// Server builds an API server without going through apiserver-runtime's
// sample-apiserver command wiring.
type Server struct {
	apiScheme     *runtime.Scheme
	openapiScheme *runtime.Scheme

	apiSchemeBuilder     runtime.SchemeBuilder
	openapiSchemeBuilder runtime.SchemeBuilder

	codecs serializer.CodecFactory

	optionsFns []func(*ServerOptions) *ServerOptions
	configFns  []start.RecommendedConfigFn

	storageProviders map[schema.GroupResource]*singletonProvider
	apis             map[schema.GroupVersionResource]serverapiserver.StorageProvider

	registeredGroupVersions map[schema.GroupVersion]struct{}
	orderedGroupVersions    []schema.GroupVersion
}

func NewServerBuilder() *Server {
	apiScheme := serverapiserver.NewScheme()
	openapiScheme := serverapiserver.NewScheme()

	return &Server{
		apiScheme:               apiScheme,
		openapiScheme:           openapiScheme,
		codecs:                  serializer.NewCodecFactory(apiScheme),
		storageProviders:        make(map[schema.GroupResource]*singletonProvider),
		apis:                    make(map[schema.GroupVersionResource]serverapiserver.StorageProvider),
		registeredGroupVersions: make(map[schema.GroupVersion]struct{}),
	}
}

func (s *Server) WithAdditionalSchemeInstallers(fns ...func(*runtime.Scheme) error) *Server {
	s.apiSchemeBuilder.Register(fns...)
	return s
}

func (s *Server) WithOptionsFns(fns ...func(*ServerOptions) *ServerOptions) *Server {
	s.optionsFns = append(s.optionsFns, fns...)
	return s
}

func (s *Server) WithConfigFns(fns ...func(*genericapiserver.RecommendedConfig) *genericapiserver.RecommendedConfig) *Server {
	for _, fn := range fns {
		s.configFns = append(s.configFns, start.RecommendedConfigFn(fn))
	}
	return s
}

func (s *Server) WithOpenAPIDefinitions(name, version string, defs openapicommon.GetOpenAPIDefinitions) *Server {
	s.configFns = append(s.configFns, start.SetOpenAPIDefinitionFn(s.openapiScheme, name, version, defs))
	return s
}

func (s *Server) DisableAuthorization() *Server {
	return s.WithOptionsFns(func(o *ServerOptions) *ServerOptions {
		o.RecommendedOptions.Authorization = nil
		return o
	})
}

func (s *Server) WithoutEtcd() *Server {
	return s.WithOptionsFns(func(o *ServerOptions) *ServerOptions {
		o.RecommendedOptions.Etcd = nil
		return o
	})
}

func (s *Server) WithResourceAndStorage(obj builderresource.Object, fn StoreFn) *Server {
	s.apiSchemeBuilder.Register(builderresource.AddToScheme(obj))
	s.openapiSchemeBuilder.Register(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(obj.GetGroupVersionResource().GroupVersion(), obj.New(), obj.NewList())
		return nil
	})

	sp := newStorageProvider(obj, fn)
	s.forGroupVersionResource(obj.GetGroupVersionResource(), sp)
	s.withStatusSubresource(obj, sp)
	return s
}

func (s *Server) Build() (*start.ApoxyServerOptions, error) {
	codec, err := s.buildCodec()
	if err != nil {
		return nil, err
	}

	opts := start.NewServerOptions(codec)
	for _, fn := range s.optionsFns {
		opts = fn(opts)
	}

	return start.NewApoxyServerOptions(
		s.apiScheme,
		s.codecs,
		codec,
		s.configFns,
		s.apis,
		opts,
	), nil
}

func (s *Server) buildCodec() (runtime.Codec, error) {
	registerGroupVersions := func(scheme *runtime.Scheme) error {
		versionsByGroup := make(map[string][]schema.GroupVersion)
		for _, gv := range s.orderedGroupVersions {
			versionsByGroup[gv.Group] = append(versionsByGroup[gv.Group], gv)
		}
		for _, versions := range versionsByGroup {
			if err := scheme.SetVersionPriority(versions...); err != nil {
				return err
			}
		}
		for _, gv := range s.orderedGroupVersions {
			metav1.AddToGroupVersion(scheme, gv)
		}
		return nil
	}

	s.apiSchemeBuilder.Register(registerGroupVersions)
	if err := s.apiSchemeBuilder.AddToScheme(s.apiScheme); err != nil {
		return nil, err
	}
	s.openapiSchemeBuilder.Register(registerGroupVersions)
	if err := s.openapiSchemeBuilder.AddToScheme(s.openapiScheme); err != nil {
		return nil, err
	}

	if len(s.orderedGroupVersions) == 0 {
		return nil, fmt.Errorf("no group versions registered")
	}

	return s.codecs.LegacyCodec(s.orderedGroupVersions...), nil
}

func (s *Server) withGroupVersions(versions ...schema.GroupVersion) {
	for _, gv := range versions {
		if _, ok := s.registeredGroupVersions[gv]; ok {
			continue
		}
		s.registeredGroupVersions[gv] = struct{}{}
		s.orderedGroupVersions = append(s.orderedGroupVersions, gv)
	}
}

func (s *Server) forGroupVersionResource(gvr schema.GroupVersionResource, sp serverapiserver.StorageProvider) {
	s.withGroupVersions(gvr.GroupVersion())

	if _, found := s.storageProviders[gvr.GroupResource()]; !found {
		s.storageProviders[gvr.GroupResource()] = &singletonProvider{provider: sp}
	}
	s.apis[gvr] = s.storageProviders[gvr.GroupResource()].Get
}

func (s *Server) forGroupVersionSubresource(gvr schema.GroupVersionResource, sp serverapiserver.StorageProvider) {
	if !strings.Contains(gvr.Resource, "/") {
		panic(fmt.Sprintf("expected subresource gvr, got %s", gvr))
	}
	s.withGroupVersions(gvr.GroupVersion())
	s.apis[gvr] = sp
}

func (s *Server) withStatusSubresource(obj builderresource.Object, parent serverapiserver.StorageProvider) {
	if _, ok := obj.(builderresource.ObjectWithStatusSubResource); !ok {
		return
	}

	parentGVR := obj.GetGroupVersionResource()
	statusGVR := parentGVR.GroupVersion().WithResource(parentGVR.Resource + "/status")
	s.forGroupVersionSubresource(statusGVR, (&statusSubresourceProvider{parent: parent}).Get)
}

type singletonProvider struct {
	once     sync.Once
	provider serverapiserver.StorageProvider
	storage  registryrest.Storage
	err      error
}

func (s *singletonProvider) Get(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (registryrest.Storage, error) {
	s.once.Do(func() {
		s.storage, s.err = s.provider(scheme, optsGetter)
	})
	return s.storage, s.err
}

type statusSubresourceProvider struct {
	parent serverapiserver.StorageProvider
}

func (s *statusSubresourceProvider) Get(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (registryrest.Storage, error) {
	parentStorage, err := s.parent(scheme, optsGetter)
	if err != nil {
		return nil, err
	}

	stdParentStorage, ok := parentStorage.(registryrest.StandardStorage)
	if !ok {
		return nil, fmt.Errorf("parent storage for status subresource must implement rest.StandardStorage: %T", parentStorage)
	}

	parentStore, ok := stdParentStorage.(*genericregistry.Store)
	if !ok {
		return nil, fmt.Errorf("status subresource parent must be *registry.Store: %T", stdParentStorage)
	}

	statusStore := *parentStore
	statusStore.UpdateStrategy = &statusSubresourceStrategy{RESTUpdateStrategy: parentStore.UpdateStrategy}

	return &statusSubresourceStorage{store: &statusStore}, nil
}

type statusSubresourceStorage struct {
	store *genericregistry.Store
}

func (s *statusSubresourceStorage) New() runtime.Object {
	return s.store.New()
}

func (s *statusSubresourceStorage) Destroy() {
	s.store.Destroy()
}

func (s *statusSubresourceStorage) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return s.store.Get(ctx, name, options)
}

func (s *statusSubresourceStorage) Update(
	ctx context.Context,
	name string,
	objInfo registryrest.UpdatedObjectInfo,
	createValidation registryrest.ValidateObjectFunc,
	updateValidation registryrest.ValidateObjectUpdateFunc,
	forceAllowCreate bool,
	options *metav1.UpdateOptions,
) (runtime.Object, bool, error) {
	return s.store.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
}

type statusSubresourceStrategy struct {
	registryrest.RESTUpdateStrategy
}

func (s *statusSubresourceStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	statusObj := obj.(builderresource.ObjectWithStatusSubResource)
	statusOld := old.(builderresource.ObjectWithStatusSubResource)

	statusObj.GetStatus().CopyTo(statusOld)
	if err := builderutil.DeepCopy(statusOld, statusObj); err != nil {
		utilruntime.HandleError(err)
	}
}

func newStorageProvider(obj builderresource.Object, fn StoreFn) serverapiserver.StorageProvider {
	return func(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (registryrest.Storage, error) {
		gvr := obj.GetGroupVersionResource()
		strategy := &defaultStrategy{
			Object:         obj,
			ObjectTyper:    scheme,
			TableConvertor: registryrest.NewDefaultTableConvertor(gvr.GroupResource()),
		}

		store := &genericregistry.Store{
			NewFunc:                  obj.New,
			NewListFunc:              obj.NewList,
			DefaultQualifiedResource: gvr.GroupResource(),
			SingularQualifiedResource: gvr.GroupResource(),
			TableConvertor:           strategy,
			CreateStrategy:           strategy,
			UpdateStrategy:           strategy,
			DeleteStrategy:           strategy,
			StorageVersioner:         gvr.GroupVersion(),
		}

		options := &generic.StoreOptions{RESTOptions: optsGetter}
		if fn != nil {
			fn(scheme, store, options)
		}

		if err := store.CompleteWithOptions(options); err != nil {
			return nil, err
		}

		return store, nil
	}
}

type defaultStrategy struct {
	Object runtime.Object
	runtime.ObjectTyper
	TableConvertor registryrest.TableConvertor
}

func (d defaultStrategy) GenerateName(base string) string {
	if d.Object == nil {
		return names.SimpleNameGenerator.GenerateName(base)
	}
	if n, ok := d.Object.(names.NameGenerator); ok {
		return n.GenerateName(base)
	}
	return names.SimpleNameGenerator.GenerateName(base)
}

func (d defaultStrategy) NamespaceScoped() bool {
	if d.Object == nil {
		return true
	}
	if n, ok := d.Object.(registryrest.Scoper); ok {
		return n.NamespaceScoped()
	}
	return true
}

func (d defaultStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	if v, ok := obj.(resourcestrategy.PrepareForCreater); ok {
		v.PrepareForCreate(ctx)
	}
}

func (d defaultStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	if v, ok := obj.(builderresource.ObjectWithStatusSubResource); ok {
		old.(builderresource.ObjectWithStatusSubResource).GetStatus().CopyTo(v)
	}
	if v, ok := obj.(resourcestrategy.PrepareForUpdater); ok {
		v.PrepareForUpdate(ctx, old)
	}
}

func (d defaultStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	if v, ok := obj.(resourcestrategy.Validater); ok {
		return v.Validate(ctx)
	}
	return nil
}

func (d defaultStrategy) AllowCreateOnUpdate() bool {
	if d.Object == nil {
		return false
	}
	if n, ok := d.Object.(resourcestrategy.AllowCreateOnUpdater); ok {
		return n.AllowCreateOnUpdate()
	}
	return false
}

func (d defaultStrategy) AllowUnconditionalUpdate() bool {
	if d.Object == nil {
		return false
	}
	if n, ok := d.Object.(resourcestrategy.AllowUnconditionalUpdater); ok {
		return n.AllowUnconditionalUpdate()
	}
	return false
}

func (d defaultStrategy) Canonicalize(obj runtime.Object) {
	if c, ok := obj.(resourcestrategy.Canonicalizer); ok {
		c.Canonicalize()
	}
}

func (d defaultStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	if v, ok := obj.(resourcestrategy.ValidateUpdater); ok {
		return v.ValidateUpdate(ctx, old)
	}
	return nil
}

func (d defaultStrategy) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	if c, ok := obj.(resourcestrategy.TableConverter); ok {
		return c.ConvertToTable(ctx, tableOptions)
	}
	return d.TableConvertor.ConvertToTable(ctx, obj, tableOptions)
}

func (d defaultStrategy) WarningsOnCreate(context.Context, runtime.Object) []string {
	return nil
}

func (d defaultStrategy) WarningsOnUpdate(context.Context, runtime.Object, runtime.Object) []string {
	return nil
}

func (d defaultStrategy) GetSingularName() string {
	if d.Object == nil {
		return ""
	}
	if n, ok := d.Object.(registryrest.SingularNameProvider); ok {
		return n.GetSingularName()
	}
	return ""
}
