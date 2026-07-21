package v1alpha1

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/duration"
)

// formatAge formats a time as a Kubernetes-style age string (e.g., "5m", "2h", "7d").
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "<unknown>"
	}
	return duration.ShortHumanDuration(time.Since(t))
}

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
