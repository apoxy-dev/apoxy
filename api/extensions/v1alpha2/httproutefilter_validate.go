package v1alpha2

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

var _ resourcestrategy.Validater = &HTTPRouteFilter{}
var _ resourcestrategy.ValidateUpdater = &HTTPRouteFilter{}

func (h *HTTPRouteFilter) Validate(ctx context.Context) field.ErrorList {
	return h.validate()
}

func (h *HTTPRouteFilter) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	hrf := &HTTPRouteFilter{}
	if mv, ok := obj.(resource.MultiVersionObject); ok {
		mv.ConvertToStorageVersion(hrf)
	} else if hrf, ok = obj.(*HTTPRouteFilter); !ok {
		return field.ErrorList{
			field.Invalid(field.NewPath("kind"), obj.GetObjectKind().GroupVersionKind().Kind, "expected HTTPRouteFilter"),
		}
	}
	return hrf.validate()
}

func (h *HTTPRouteFilter) validate() field.ErrorList {
	errs := field.ErrorList{}
	specPath := field.NewPath("spec")

	if h.Spec.Compressor != nil {
		errs = append(errs, validateCompressorSpec(h.Spec.Compressor, specPath.Child("compressor"))...)
	}

	return errs
}

func validateCompressorSpec(spec *CompressorSpec, fldPath *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	if spec.Disabled != nil && *spec.Disabled {
		// When disabled, no other fields may be set.
		if len(spec.Algorithms) > 0 {
			errs = append(errs, field.Forbidden(fldPath.Child("algorithms"), "cannot be set when disabled is true"))
		}
		if spec.MinContentLength != nil {
			errs = append(errs, field.Forbidden(fldPath.Child("minContentLength"), "cannot be set when disabled is true"))
		}
		if len(spec.ContentType) > 0 {
			errs = append(errs, field.Forbidden(fldPath.Child("contentType"), "cannot be set when disabled is true"))
		}
		return errs
	}

	if spec.MinContentLength != nil && *spec.MinContentLength < 50 {
		errs = append(errs, field.Invalid(fldPath.Child("minContentLength"), *spec.MinContentLength, "must be at least 50"))
	}

	return errs
}
