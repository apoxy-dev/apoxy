package v1alpha2

import (
	"time"

	"k8s.io/apimachinery/pkg/util/duration"
)

// formatAge formats a time as a Kubernetes-style age string (e.g., "5m", "2h", "7d").
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "<unknown>"
	}
	return duration.ShortHumanDuration(time.Since(t))
}
