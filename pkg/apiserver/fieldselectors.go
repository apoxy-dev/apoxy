package apiserver

import (
	"fmt"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/generic"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
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
	case *corev1alpha3.DomainRecord:
		fs["spec.zone"] = o.Spec.Zone
		fs["spec.name"] = o.Spec.Name
		fs["status.type"] = o.Status.Type
	}

	return labels.Set(om.Labels), fs, nil
}

// selectableFieldConversion returns a FieldLabelConversionFunc that accepts
// metadata.name, metadata.namespace, and any additional fields.
func selectableFieldConversion(extra ...string) func(label, value string) (string, string, error) {
	allowed := map[string]bool{
		"metadata.name":      true,
		"metadata.namespace": true,
	}
	for _, f := range extra {
		allowed[f] = true
	}
	return func(label, value string) (string, string, error) {
		if allowed[label] {
			return label, value, nil
		}
		return "", "", fmt.Errorf("%q is not a known field selector", label)
	}
}

// registerFieldLabelConversions registers custom field selectors so the API
// server accepts them in ?fieldSelector= query parameters. Without this
// registration, only metadata.name and metadata.namespace are accepted.
func registerFieldLabelConversions(s *runtime.Scheme) error {
	if err := s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{Group: corev1alpha2.GroupName, Version: "v1alpha2", Kind: "Domain"},
		selectableFieldConversion("spec.zone", "status.phase"),
	); err != nil {
		return err
	}
	if err := s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{Group: corev1alpha2.GroupName, Version: "v1alpha2", Kind: "DomainZone"},
		selectableFieldConversion("status.phase"),
	); err != nil {
		return err
	}
	if err := s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{Group: corev1alpha2.GroupName, Version: "v1alpha2", Kind: "Proxy"},
		selectableFieldConversion("spec.provider"),
	); err != nil {
		return err
	}
	if err := s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{Group: corev1alpha2.GroupName, Version: "v1alpha2", Kind: "Backend"},
		selectableFieldConversion("spec.protocol"),
	); err != nil {
		return err
	}
	if err := s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{Group: corev1alpha3.GroupName, Version: "v1alpha3", Kind: "DomainRecord"},
		selectableFieldConversion("spec.zone", "spec.name", "status.type"),
	); err != nil {
		return err
	}
	return nil
}
