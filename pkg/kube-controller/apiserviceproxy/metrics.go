package apiserviceproxy

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/pkg/cert/reload"
)

const (
	// CertExpiryMetricName is the gauge the CLI scrapes from a running
	// pod to confirm `apoxy k8s certs rotate --no-restart` took effect.
	// Exported so the rotate-flow caller doesn't hard-code the string.
	CertExpiryMetricName = "apoxy_kube_controller_cert_expiry_seconds"

	// CertRenewalsMetricName is the auto-renewal outcome counter (vector
	// with a `result` label). Exported so integration tests and alert
	// rules can reference the canonical name.
	CertRenewalsMetricName = "apoxy_kube_controller_cert_renewals_total"

	// Event reasons emitted by the auto-renewer on the kube-controller
	// Deployment. Exported so tests and docs can match the canonical
	// strings rather than copying literals.
	EventReasonCertRenewed       = "CertRenewed"
	EventReasonCertRenewalFailed = "CertRenewalFailed"

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
	certRenewals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apoxy_kube_controller_cert_renewals_total",
			Help: "Total kube-controller upstream-cert auto-renewal attempts.",
		},
		[]string{"result"},
	)
	// certRenewSkipped tracks ticks where the live cert was still well
	// inside its validity window. Alerting on this counter going flat
	// catches a stuck auto-renewal loop without firing during normal
	// pre-renewal steady state.
	certRenewSkipped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "apoxy_kube_controller_cert_renewal_skipped_total",
			Help: "Auto-renewal ticks that found the cert still above the renewal threshold.",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(certReloads, certExpiry, certRenewals, certRenewSkipped)
}

// certReloadMetrics adapts the kube-controller cert-reload counters to the
// shared reload.Metrics interface, so the watcher in pkg/cert/reload keeps
// emitting the long-standing apoxy_kube_controller_cert_* series that
// existing dashboards and alerts depend on.
type certReloadMetrics struct{}

var _ reload.Metrics = certReloadMetrics{}

func (certReloadMetrics) ReloadAttempt(success bool) {
	result := resultFailure
	if success {
		result = resultSuccess
	}
	certReloads.WithLabelValues(result).Inc()
}

func (certReloadMetrics) SetExpiry(t time.Time) {
	certExpiry.Set(float64(t.Unix()))
}
