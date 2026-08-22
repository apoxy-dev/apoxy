package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// AllKinds is every kind of the group, for a caller that must register the
// group in a scheme it does not own. The connect result kinds (MetricSeriesSet
// and the snapshot kinds) have no resource.Object of their own, so a builder
// that mounts custom storage cannot pick them up from a resource list.
func AllKinds() []runtime.Object {
	return []runtime.Object{
		&Metric{},
		&MetricList{},
		&MetricSource{},
		&MetricSourceList{},
		&MetricSeriesSet{},
		&GatewayMetrics{},
		&HTTPRouteMetrics{},
		&ProxyMetrics{},
		&ServiceMetrics{},
		&VPCNetworkMetrics{},
	}
}
