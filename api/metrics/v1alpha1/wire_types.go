package v1alpha1

// Measures is one recipe's output columns for a window. Values are plain JSON
// numbers, integral where the catalog declares the measure type as integer.
// Units are not encoded in the value: every snapshot and every MetricSeriesSet
// echoes a units map taken from the catalog.
type Measures map[string]float64

// MetricsMap is keyed by Metric name. Each value is that recipe's measures, so
// a snapshot entry and a series point carry the same measure names by
// construction.
type MetricsMap map[string]Measures
