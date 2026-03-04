package v1alpha3

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/duration"
)

// formatMultiValue formats a slice of values for table display, showing
// the first value truncated and a count of remaining values.
func formatMultiValue(values []string, maxLen int) string {
	if len(values) == 0 {
		return ""
	}
	v := truncateString(values[0], maxLen)
	if n := len(values) - 1; n > 0 {
		v += fmt.Sprintf(" (+%d)", n)
	}
	return v
}

// truncateString truncates a string to maxLen characters, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// formatAge formats a time as a Kubernetes-style age string (e.g., "5m", "2h", "7d").
func formatAge(t time.Time) string {
	if t.IsZero() {
		return "<unknown>"
	}
	return duration.ShortHumanDuration(time.Since(t))
}
