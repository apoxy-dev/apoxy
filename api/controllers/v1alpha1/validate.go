package v1alpha1

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &Proxy{}

// Default sets the default values for a Proxy.
func (r *Proxy) Default() {
	if r.Status.Phase == "" {
		r.Status.Phase = ProxyPhasePending
	}
	if r.Spec.DrainTimeout == nil {
		r.Spec.DrainTimeout = &metav1.Duration{Duration: DefaultDrainTimeout}
	}
	if r.Spec.MinimumDrainTime == nil {
		r.Spec.MinimumDrainTime = &metav1.Duration{Duration: DefaultDrainTimeout}
	}
}

var _ resourcestrategy.Validater = &Proxy{}
var _ resourcestrategy.ValidateUpdater = &Proxy{}

func (r *Proxy) validate() field.ErrorList {
	errs := field.ErrorList{}
	spec := r.Spec

	if spec.MinimumDrainTime.Duration > spec.DrainTimeout.Duration {
		errs = append(errs, field.Invalid(field.NewPath("spec", "minimumDrainTime"), r.Spec.MinimumDrainTime, "minimumDrainTime must be less than or equal to drainTimeout"))
	}

	return errs
}

func (r *Proxy) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *Proxy) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	p := obj.(*Proxy)
	return p.validate()
}
