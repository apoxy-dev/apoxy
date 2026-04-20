package resourcestrategy

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Defaulter is invoked when deserializing an object to set default values.
type Defaulter interface {
	Default()
}

// Validater is invoked before an object is stored to validate it during creation.
type Validater interface {
	Validate(ctx context.Context) field.ErrorList
}

// ValidateUpdater is invoked before an object is stored to validate it during update.
type ValidateUpdater interface {
	ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList
}

// PrepareForCreater is invoked before an object is stored during creation.
type PrepareForCreater interface {
	PrepareForCreate(ctx context.Context)
}

// PrepareForUpdater is invoked before an object is stored during update.
type PrepareForUpdater interface {
	PrepareForUpdate(ctx context.Context, old runtime.Object)
}

// AllowCreateOnUpdater controls whether a resource can be created via PUT.
type AllowCreateOnUpdater interface {
	AllowCreateOnUpdate() bool
}

// AllowUnconditionalUpdater controls whether unconditional updates are allowed.
type AllowUnconditionalUpdater interface {
	AllowUnconditionalUpdate() bool
}

// Canonicalizer is invoked before an object is stored to canonicalize its format.
type Canonicalizer interface {
	Canonicalize()
}

// TableConverter converts a resource to table format for kubectl output.
type TableConverter interface {
	ConvertToTable(ctx context.Context, tableOptions runtime.Object) (*metav1.Table, error)
}
