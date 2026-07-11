// Package secretstore implements the REST plumbing that makes SecretStore
// values write-only: a redacting wrapper that strips stored values from every
// main-resource response, a "values" subresource that is the single path
// through which values are written and (by internal identities only) read,
// and the authorizer gate that enforces the read restriction.
//
// Values live on the stored SecretStore's top-level Data field (mirroring
// corev1.Secret), so the main resource and the values subresource share one
// logical store; only the response shaping differs.
package secretstore

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	registryrest "k8s.io/apiserver/pkg/registry/rest"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// redact returns a value-free deep copy when the object carries secret data.
// Objects are deep-copied before mutation because the underlying store (and
// especially the watch cacher) hands out shared instances.
func redact(obj runtime.Object) runtime.Object {
	switch o := obj.(type) {
	case *corev1alpha.SecretStore:
		if o.Data == nil {
			return o
		}
		c := o.DeepCopy()
		c.Data = nil
		return c
	case *corev1alpha.SecretStoreList:
		needs := false
		for i := range o.Items {
			if o.Items[i].Data != nil {
				needs = true
				break
			}
		}
		if !needs {
			return o
		}
		c := o.DeepCopy()
		for i := range c.Items {
			c.Items[i].Data = nil
		}
		return c
	}
	return obj
}

// redactedStorage wraps the SecretStore main-resource storage and strips
// stored values from every response. Writes pass through untouched — the
// object's PrepareForCreate/PrepareForUpdate hooks already discard
// client-supplied values on this path.
type redactedStorage struct {
	*genericregistry.Store
}

var (
	_ registryrest.StandardStorage      = &redactedStorage{}
	_ registryrest.Scoper               = &redactedStorage{}
	_ registryrest.SingularNameProvider = &redactedStorage{}
)

func (r *redactedStorage) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	obj, err := r.Store.Get(ctx, name, options)
	if err != nil {
		return obj, err
	}
	return redact(obj), nil
}

func (r *redactedStorage) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	obj, err := r.Store.List(ctx, options)
	if err != nil {
		return obj, err
	}
	return redact(obj), nil
}

func (r *redactedStorage) Create(ctx context.Context, obj runtime.Object, createValidation registryrest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	out, err := r.Store.Create(ctx, obj, createValidation, options)
	if err != nil {
		return out, err
	}
	return redact(out), nil
}

func (r *redactedStorage) Update(ctx context.Context, name string, objInfo registryrest.UpdatedObjectInfo, createValidation registryrest.ValidateObjectFunc, updateValidation registryrest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	out, created, err := r.Store.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
	if err != nil {
		return out, created, err
	}
	return redact(out), created, nil
}

func (r *redactedStorage) Delete(ctx context.Context, name string, deleteValidation registryrest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	out, deleted, err := r.Store.Delete(ctx, name, deleteValidation, options)
	if err != nil {
		return out, deleted, err
	}
	return redact(out), deleted, nil
}

func (r *redactedStorage) DeleteCollection(ctx context.Context, deleteValidation registryrest.ValidateObjectFunc, options *metav1.DeleteOptions, listOptions *internalversion.ListOptions) (runtime.Object, error) {
	out, err := r.Store.DeleteCollection(ctx, deleteValidation, options, listOptions)
	if err != nil {
		return out, err
	}
	return redact(out), nil
}

func (r *redactedStorage) Watch(ctx context.Context, options *internalversion.ListOptions) (watch.Interface, error) {
	w, err := r.Store.Watch(ctx, options)
	if err != nil {
		return w, err
	}
	return watch.Filter(w, func(e watch.Event) (watch.Event, bool) {
		if e.Object != nil {
			e.Object = redact(e.Object)
		}
		return e, true
	}), nil
}

// valuesStorage serves secretstores/<name>/values: GET returns the values
// document (request-layer authorization restricts this to internal
// identities), PUT replaces the map, and JSON merge-patch sets or (via null)
// deletes individual keys. It reuses the parent store with a values-specific
// update strategy, mirroring the builder's status-subresource pattern.
type valuesStorage struct {
	store *genericregistry.Store
}

var (
	_ registryrest.Getter  = &valuesStorage{}
	_ registryrest.Updater = &valuesStorage{}
	_ registryrest.Patcher = &valuesStorage{}
	_ registryrest.Scoper  = &valuesStorage{}
)

func (v *valuesStorage) New() runtime.Object {
	return &corev1alpha.SecretStoreValues{}
}

func (v *valuesStorage) Destroy() {}

func (v *valuesStorage) NamespaceScoped() bool { return false }

// valuesView projects the stored parent onto the subresource document.
func valuesView(store *corev1alpha.SecretStore) *corev1alpha.SecretStoreValues {
	vals := &corev1alpha.SecretStoreValues{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1alpha.SchemeGroupVersion.String(),
			Kind:       "SecretStoreValues",
		},
		ObjectMeta: *store.ObjectMeta.DeepCopy(),
		Scopes:     append([]string(nil), store.Spec.Scopes...),
	}
	if len(store.Data) > 0 {
		vals.Data = make(map[string]string, len(store.Data))
		for k, val := range store.Data {
			vals.Data[k] = val
		}
	}
	return vals
}

func (v *valuesStorage) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	obj, err := v.store.Get(ctx, name, options)
	if err != nil {
		return nil, err
	}
	return valuesView(obj.(*corev1alpha.SecretStore)), nil
}

func (v *valuesStorage) Update(ctx context.Context, name string, objInfo registryrest.UpdatedObjectInfo, createValidation registryrest.ValidateObjectFunc, updateValidation registryrest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	out, created, err := v.store.Update(ctx, name, &valuesUpdatedObjectInfo{delegate: objInfo}, createValidation, updateValidation, false, options)
	if err != nil {
		return nil, created, err
	}
	return valuesView(out.(*corev1alpha.SecretStore)), created, nil
}

// valuesUpdatedObjectInfo adapts the wire-level SecretStoreValues transform
// (PUT body or applied patch) onto the stored parent kind: the handler's
// objInfo is fed the current values view and its output map is written back
// to a copy of the stored SecretStore, with status derived from the result.
type valuesUpdatedObjectInfo struct {
	delegate registryrest.UpdatedObjectInfo
}

func (i *valuesUpdatedObjectInfo) Preconditions() *metav1.Preconditions {
	return i.delegate.Preconditions()
}

func (i *valuesUpdatedObjectInfo) UpdatedObject(ctx context.Context, oldObj runtime.Object) (runtime.Object, error) {
	store, ok := oldObj.(*corev1alpha.SecretStore)
	if !ok {
		return nil, fmt.Errorf("values subresource parent has unexpected type %T", oldObj)
	}
	updated, err := i.delegate.UpdatedObject(ctx, valuesView(store))
	if err != nil {
		return nil, err
	}
	vals, ok := updated.(*corev1alpha.SecretStoreValues)
	if !ok {
		return nil, fmt.Errorf("values subresource update produced unexpected type %T", updated)
	}
	out := store.DeepCopy()
	out.Data = vals.Data
	out.Status.Keys = corev1alpha.ComputeKeyStatus(out.Data)
	// The subresource never moves metadata; a client-supplied resourceVersion
	// on the values document still applies optimistic concurrency.
	if rv := vals.ResourceVersion; rv != "" {
		out.ResourceVersion = rv
	}
	return out, nil
}

// valuesUpdateStrategy bypasses the parent strategy's PrepareForUpdate (which
// carries old values forward and would turn every values write into a no-op)
// while keeping the rest of its behavior. Spec changes are not possible on
// this path — valuesUpdatedObjectInfo only touches Data and Status.
type valuesUpdateStrategy struct {
	registryrest.RESTUpdateStrategy
}

func (valuesUpdateStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {}
