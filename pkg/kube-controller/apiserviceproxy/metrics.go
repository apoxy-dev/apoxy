package apiserviceproxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// CertExpiryMetricName is the gauge the CLI scrapes from a running
	// pod to confirm `apoxy k8s certs rotate --no-restart` took effect.
	// Exported so the rotate-flow caller doesn't hard-code the string.
	CertExpiryMetricName = "apoxy_kube_controller_cert_expiry_seconds"

	resultSuccess = "success"
	resultFailure = "failure"
)

var (
	certReloads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apoxy_kube_controller_cert_reloads_total",
			Help: "Total kube-controller upstream-cert reload attempts.",
		},
		[]string{"result"},
	)
	certExpiry = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: CertExpiryMetricName,
			Help: "Unix-seconds expiry (NotAfter) of the live upstream client cert.",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(certReloads, certExpiry)
}
