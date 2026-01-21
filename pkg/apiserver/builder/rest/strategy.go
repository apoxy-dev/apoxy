// Package rest provides REST storage and strategy implementations for API resources.
// These interfaces are compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy.
package rest

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"

	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
)

// TableConverter is implemented by resources that support kubectl table output.
// Compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy.TableConverter
type TableConverter interface {
	ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error)
}

// Validater is implemented by resources that support create validation.
// Compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy.Validater
type Validater interface {
	Validate(ctx context.Context) field.ErrorList
}

// ValidateUpdater is implemented by resources that support update validation.
// Compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy.ValidateUpdater
type ValidateUpdater interface {
	ValidateUpdate(ctx context.Context, old runtime.Object) field.ErrorList
}

// Defaulter is implemented by resources that support defaulting values.
// Compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy.Defaulter
type Defaulter interface {
	Default()
}

// PrepareForCreater is implemented by resources that need custom preparation before creation.
// Compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy.PrepareForCreater
type PrepareForCreater interface {
	PrepareForCreate(ctx context.Context)
}

// PrepareForUpdater is implemented by resources that need custom preparation before update.
// Compatible with sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy.PrepareForUpdater
type PrepareForUpdater interface {
	PrepareForUpdate(ctx context.Context, old runtime.Object)
}

// DefaultStrategy provides a default implementation for REST strategies.
// It implements RESTCreateStrategy, RESTUpdateStrategy, RESTDeleteStrategy,
// TableConvertor, and ResetFieldsStrategy interfaces.
type DefaultStrategy struct {
	Object      resource.Object
	ObjectTyper runtime.ObjectTyper
}

// NewDefaultStrategy creates a new DefaultStrategy for the given object.
func NewDefaultStrategy(obj resource.Object, typer runtime.ObjectTyper) *DefaultStrategy {
	return &DefaultStrategy{
		Object:      obj,
		ObjectTyper: typer,
	}
}

// NamespaceScoped returns true if the object is namespace scoped.
func (s *DefaultStrategy) NamespaceScoped() bool {
	return s.Object.NamespaceScoped()
}

// ObjectKinds returns the group version kinds of the object.
// Required by RESTCreateStrategy, RESTUpdateStrategy, RESTDeleteStrategy.
func (s *DefaultStrategy) ObjectKinds(obj runtime.Object) ([]schema.GroupVersionKind, bool, error) {
	return s.ObjectTyper.ObjectKinds(obj)
}

// Recognizes returns true if the scheme recognizes the kind.
// Required by RESTCreateStrategy, RESTUpdateStrategy, RESTDeleteStrategy.
func (s *DefaultStrategy) Recognizes(gvk schema.GroupVersionKind) bool {
	return s.ObjectTyper.Recognizes(gvk)
}

// GenerateName generates a name for the object if needed.
// Required by RESTCreateStrategy.
func (s *DefaultStrategy) GenerateName(base string) string {
	return names.SimpleNameGenerator.GenerateName(base)
}

// PrepareForCreate prepares an object for creation by delegating to the object's
// PrepareForCreate method if it implements PrepareForCreater.
func (s *DefaultStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	if v, ok := obj.(PrepareForCreater); ok {
		v.PrepareForCreate(ctx)
	}
}

// PrepareForUpdate prepares an object for update by preserving the status from the
// old object and delegating to the object's PrepareForUpdate method if it implements
// PrepareForUpdater.
func (s *DefaultStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// Preserve status from old object (status is updated via /status subresource)
	if v, ok := obj.(resource.ObjectWithStatusSubResource); ok {
		old.(resource.ObjectWithStatusSubResource).GetStatus().CopyTo(v)
	}
	if v, ok := obj.(PrepareForUpdater); ok {
		v.PrepareForUpdate(ctx, old)
	}
}

// Validate validates a new object.
func (s *DefaultStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	if v, ok := obj.(Validater); ok {
		return v.Validate(ctx)
	}
	return field.ErrorList{}
}

// ValidateUpdate validates an update.
func (s *DefaultStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	if v, ok := obj.(ValidateUpdater); ok {
		return v.ValidateUpdate(ctx, old)
	}
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the object.
func (s *DefaultStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

// WarningsOnUpdate returns warnings for the update of the object.
func (s *DefaultStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// AllowCreateOnUpdate returns true if the object can be created via PUT.
func (s *DefaultStrategy) AllowCreateOnUpdate() bool {
	return false
}

// AllowUnconditionalUpdate returns true if unconditional updates are allowed.
func (s *DefaultStrategy) AllowUnconditionalUpdate() bool {
	return false
}

// Canonicalize normalizes the object after validation.
func (s *DefaultStrategy) Canonicalize(obj runtime.Object) {
}

// GetResetFields returns fields that should be reset on update.
// Required by ResetFieldsStrategy.
func (s *DefaultStrategy) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	return nil
}

// GetAttrs returns labels, fields, and error for the given object.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	accessor, err := metaAccessor(obj)
	if err != nil {
		return nil, nil, err
	}
	return labels.Set(accessor.GetLabels()), SelectableFields(accessor), nil
}

// SelectableFields returns a field set that can be used for filtering.
func SelectableFields(accessor metav1.Object) fields.Set {
	return fields.Set{
		"metadata.name":      accessor.GetName(),
		"metadata.namespace": accessor.GetNamespace(),
	}
}

// MatchFunc returns a selection predicate for the given label and field selectors.
func MatchFunc(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}

// ConvertToTable converts an object to a table representation.
// This is used by kubectl get.
func (s *DefaultStrategy) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	if tc, ok := obj.(TableConverter); ok {
		return tc.ConvertToTable(ctx, tableOptions)
	}
	return rest.NewDefaultTableConvertor(s.Object.GetGroupVersionResource().GroupResource()).ConvertToTable(ctx, obj, tableOptions)
}

// metaAccessor returns the ObjectMeta accessor for the object.
func metaAccessor(obj runtime.Object) (metav1.Object, error) {
	if accessor, ok := obj.(metav1.ObjectMetaAccessor); ok {
		return accessor.GetObjectMeta(), nil
	}
	return nil, nil
}

// Verify DefaultStrategy implements required interfaces.
var (
	_ rest.RESTCreateStrategy      = &DefaultStrategy{}
	_ rest.RESTUpdateStrategy      = &DefaultStrategy{}
	_ rest.RESTDeleteStrategy      = &DefaultStrategy{}
	_ rest.TableConvertor          = &DefaultStrategy{}
	_ rest.ResetFieldsStrategy     = &DefaultStrategy{}
)
