package v1alpha1

import (
	"context"
	"fmt"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var (
	_ resourcestrategy.Validater       = &VPCNetwork{}
	_ resourcestrategy.ValidateUpdater = &VPCNetwork{}
)

func (n *VPCNetwork) Validate(ctx context.Context) field.ErrorList {
	return n.validate()
}

// ValidateUpdate checks only spec changes, so that status writes and deletes
// of an older network do not fail.
func (n *VPCNetwork) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	if n.DeletionTimestamp != nil {
		return nil
	}
	if old, ok := obj.(*VPCNetwork); ok && apiequality.Semantic.DeepEqual(old.Spec, n.Spec) {
		return nil
	}
	return n.validate()
}

func (n *VPCNetwork) validate() field.ErrorList {
	var errs field.ErrorList
	if mtu := n.Spec.MTU; mtu != 0 && (mtu < DefaultMTU || mtu > MaxMTU) {
		errs = append(errs, field.Invalid(field.NewPath("spec", "mtu"), mtu,
			fmt.Sprintf("must be from %d to %d", DefaultMTU, MaxMTU)))
	}
	return errs
}
