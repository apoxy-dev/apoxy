package apiserver

import (
	"fmt"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// customGetAttrs returns labels and fields for field selector filtering.
// It extends the default metadata.name with per-type custom fields.
func customGetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	provider, ok := obj.(resource.Object)
	if !ok {
		return nil, nil, fmt.Errorf("object of type %T does not implement resource.Object", obj)
	}
	om := provider.GetObjectMeta()
	fs := generic.ObjectMetaFieldsSet(om, false) // non-namespaced

	switch o := obj.(type) {
	case *corev1alpha2.Domain:
		fs["spec.zone"] = o.Spec.Zone
		fs["status.phase"] = string(o.Status.Phase)
	case *corev1alpha2.DomainZone:
		fs["status.phase"] = string(o.Status.Phase)
	case *corev1alpha2.Proxy:
		fs["spec.provider"] = string(o.Spec.Provider)
	case *corev1alpha2.Backend:
		fs["spec.protocol"] = string(o.Spec.Protocol)
	}

	return labels.Set(om.Labels), fs, nil
}
