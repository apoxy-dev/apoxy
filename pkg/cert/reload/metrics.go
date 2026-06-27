package reload

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Metrics records reload outcomes and live-cert expiry. Implementations must
// be safe for concurrent use. A nil Metrics disables metric recording, which
// lets callers keep their own pre-existing series by passing an adapter
// instead of the default below.
type Metrics interface {
	// ReloadAttempt records one reload attempt and whether it swapped in a
	// new bundle. Identical-content resyncs are no-ops and are not recorded.
	ReloadAttempt(success bool)
	// SetExpiry publishes the NotAfter of the live leaf.
	SetExpiry(t time.Time)
}

const (
	resultSuccess = "success"
	resultFailure = "failure"
)

var (
	defaultReloads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apoxy_tls_cert_reloads_total",
			Help: "Total TLS cert hot-reload attempts, by component and result.",
		},
		[]string{"component", "result"},
	)
	defaultExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apoxy_tls_cert_expiry_seconds",
			Help: "Unix-seconds expiry (NotAfter) of the live TLS cert, by component.",
		},
		[]string{"component"},
	)
)

func init() {
	crmetrics.Registry.MustRegister(defaultReloads, defaultExpiry)
}

// DefaultMetrics records to the shared apoxy_tls_cert_* series, labelled by
// component. Multiple Reloaders may share the same component label.
func DefaultMetrics(component string) Metrics {
	return defaultMetrics{component: component}
}

type defaultMetrics struct{ component string }

func (m defaultMetrics) ReloadAttempt(success bool) {
	result := resultFailure
	if success {
		result = resultSuccess
	}
	defaultReloads.WithLabelValues(m.component, result).Inc()
}

func (m defaultMetrics) SetExpiry(t time.Time) {
	defaultExpiry.WithLabelValues(m.component).Set(float64(t.Unix()))
}
