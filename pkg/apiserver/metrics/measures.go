package metrics

import (
	"math"

	metricsv1alpha1 "github.com/apoxy-dev/apoxy/api/metrics/v1alpha1"
)

// RoundLatencyMillis is the one copy of the latency rounding rule. A
// percentile is interpolated from a histogram, so its fractional part is
// noise; both typed surfaces report it as whole milliseconds, and they must
// agree. A value that is not finite collapses to zero, which is what an empty
// bucket means.
func RoundLatencyMillis(ms float64) float64 {
	if math.IsNaN(ms) || math.IsInf(ms, 0) {
		return 0
	}
	return math.Round(ms)
}

// UnitsFor collects the units of every measure the recipes report, which is
// what a snapshot and a series set echo so a client formats without parsing.
func UnitsFor(recipes ...Recipe) map[string]string {
	units := map[string]string{}
	for _, rec := range recipes {
		for name, unit := range rec.Units {
			if unit != "" {
				units[name] = unit
			}
		}
	}
	if len(units) == 0 {
		return nil
	}
	return units
}

// Measures is the wire map every measure set uses, aliased so a read model
// does not import the API group for one type.
type Measures = metricsv1alpha1.Measures

// MetricsMap is the per-recipe measure map, keyed by Metric name.
type MetricsMap = metricsv1alpha1.MetricsMap
