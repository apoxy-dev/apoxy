package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// noHeaders reports whether the caller asked for a headerless table.
func noHeaders(tableOptions runtime.Object) bool {
	opt, ok := tableOptions.(*metav1.TableOptions)
	return ok && opt.NoHeaders
}

// setListMeta copies list metadata onto a rendered table.
func setListMeta(table *metav1.Table, meta *metav1.ListMeta) {
	table.ResourceVersion = meta.ResourceVersion
	table.Continue = meta.Continue
	table.RemainingItemCount = meta.RemainingItemCount
}
