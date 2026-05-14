package apiserviceproxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// certReloads counts cert-reload attempts by outcome.
	certReloads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apoxy_kube_controller_cert_reloads_total",
			Help: "Total kube-controller upstream-cert reload attempts.",
		},
		[]string{"result"},
	)
	// certExpiry tracks the live cert's NotAfter as a unix seconds gauge.
	// Useful for an absolute alert ("cert expires in <14d") that doesn't
	// need to know about the controller's reload cadence.
	certExpiry = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "apoxy_kube_controller_cert_expiry_seconds",
			Help: "Unix-seconds expiry (NotAfter) of the live upstream client cert.",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(certReloads, certExpiry)
}
