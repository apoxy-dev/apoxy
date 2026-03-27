package controllers

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// MirrorSyncedResources counts successful resource sync operations.
	MirrorSyncedResources = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_mirror_synced_resources_total",
			Help: "Total mirror resource sync operations that succeeded.",
		},
		[]string{"resource_type"},
	)
	// MirrorSyncErrors counts failed resource sync operations.
	MirrorSyncErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tunnel_mirror_sync_errors_total",
			Help: "Total mirror resource sync operations that failed.",
		},
		[]string{"resource_type"},
	)
	// MirrorHeartbeatFailures counts heartbeat lease renewal failures.
	MirrorHeartbeatFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tunnel_mirror_heartbeat_failures_total",
			Help: "Total mirror heartbeat lease renewal failures.",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		MirrorSyncedResources,
		MirrorSyncErrors,
		MirrorHeartbeatFailures,
	)
}
