package builder

import (
	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	registryrest "k8s.io/apiserver/pkg/registry/rest"

	serverapiserver "github.com/apoxy-dev/apoxy/pkg/apiserver/server/apiserver"
)

// WithEvents serves the upstream events.k8s.io/v1 Events API from this server,
// backed by store (which must be persistent + watchable, e.g. kine, via the
// same StoreFn seam as WithResourceAndStorage). Callers get
// LIST/GET/WATCH/CREATE/UPDATE/DELETE and the client-go events broadcaster works
// against it unchanged.
//
// Events is an upstream k8s type, not a builderresource.Object, so it can't go
// through WithResourceAndStorage. Everything specific to Events is baked in here
// -- the GroupVersionResource, the namespaced scope, the "event" singular, the
// eventsv1 scheme install, and the {group, __internal} storage-version alias the
// generic store's codec needs -- so the call site is just WithEvents(store) with
// no room to get those wrong.
//
// It is a deliberate opt-in, not a server default, for two reasons:
//
//   - The store carries no TTL, so the CALLER owns Event GC (a pruner). Serving
//     Events does not bound their growth; defaulting it on would hand every
//     consumer an unbounded Events table.
//   - Serving Events here is a LOCAL surface: direct/loopback clients see it. It
//     is never aggregated into a host kube-apiserver -- the host owns the
//     built-in events.k8s.io group and an APIService cannot override it -- so a
//     host cluster's `kubectl get events` shows the host's Events, not these.
//     Reach these through this server's own (loopback) endpoint.
func (s *Server) WithEvents(store StoreFn) *Server {
	gvr := eventsv1.SchemeGroupVersion.WithResource("events")
	s.apiSchemeBuilder.Register(installEventsScheme)
	s.openapiSchemeBuilder.Register(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(gvr.GroupVersion(), &eventsv1.Event{}, &eventsv1.EventList{})
		return nil
	})
	sp := newExternalStorageProvider(
		gvr,
		func() runtime.Object { return &eventsv1.Event{} },
		func() runtime.Object { return &eventsv1.EventList{} },
		true,    // Events are namespace-scoped.
		"event", // Discovery singular.
		store,
	)
	s.forGroupVersionResource(gvr, sp)
	return s
}

// installEventsScheme registers events.k8s.io/v1 Event/EventList in the api
// scheme, plus the {group, __internal} alias the kine-backed generic store's
// storage codec requires. The same Go type is registered at both the real
// GroupVersion and the internal version, so no conversion is needed (the
// internal "hub" IS the v1 type) -- mirroring the dual registration
// builderresource.AddToScheme performs for storage-version CRDs.
func installEventsScheme(scheme *runtime.Scheme) error {
	if err := eventsv1.AddToScheme(scheme); err != nil {
		return err
	}
	scheme.AddKnownTypes(
		schema.GroupVersion{Group: eventsv1.GroupName, Version: runtime.APIVersionInternal},
		&eventsv1.Event{}, &eventsv1.EventList{},
	)
	return nil
}

// newExternalStorageProvider builds a kine-backed genericregistry.Store for a
// resource whose Go type is NOT a builderresource.Object (an upstream k8s type
// such as events.k8s.io/v1 Event). It mirrors newStorageProvider but runs
// defaultStrategy with Object == nil (its per-object hooks operate on the request
// object, not on Object), forces scope via namespaceScoped, and turns off
// generation tracking (external types carry no Spec to diff). It adds no status
// subresource. This is the shared engine WithEvents (and any future upstream-type
// method) is built on; it is intentionally unexported so registration stays a
// purpose-built one-liner rather than a many-argument public method.
func newExternalStorageProvider(
	gvr schema.GroupVersionResource,
	newFn, newListFn func() runtime.Object,
	namespaceScoped bool,
	singularName string,
	fn StoreFn,
) serverapiserver.StorageProvider {
	return func(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (registryrest.Storage, error) {
		scoped := namespaceScoped
		strategy := &defaultStrategy{
			Object:          nil,
			ObjectTyper:     scheme,
			TableConvertor:  registryrest.NewDefaultTableConvertor(gvr.GroupResource()),
			trackGeneration: false,
			namespaceScoped: &scoped,
		}

		singular := gvr.GroupResource()
		if singularName != "" {
			singular.Resource = singularName
		}

		store := &genericregistry.Store{
			NewFunc:                   newFn,
			NewListFunc:               newListFn,
			DefaultQualifiedResource:  gvr.GroupResource(),
			SingularQualifiedResource: singular,
			TableConvertor:            strategy,
			CreateStrategy:            strategy,
			UpdateStrategy:            strategy,
			DeleteStrategy:            strategy,
			StorageVersioner:          gvr.GroupVersion(),
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
