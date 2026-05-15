package apiserviceproxy

import (
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// Default cadence + threshold for cert auto-renewal. The renewer attempts
// renewal once per RenewInterval, and only when the live cert's remaining
// validity drops below RenewThreshold. With cosmos's 365-day certs that
// means each pod self-renews ~once a year, well before expiry.
const (
	DefaultRenewInterval  = time.Hour
	DefaultRenewThreshold = 30 * 24 * time.Hour
)

// Options contains the configuration for the APIServiceProxy.
type Options struct {
	ProjectID      uuid.UUID
	Namespace      string
	ServiceName    string
	ClusterName    string
	Token          string
	KubeconfigPath string
	APIHost        string
	// LocalMode disables upstream TLS verification — cosmos-tls in dev is
	// self-signed by cert-manager and not present in the pod's system
	// trust store. Only set in dev installs (`apoxy k8s install --local`).
	LocalMode bool
	// CertDir is the path the apiz-cert Secret is mounted at inside the
	// pod. When set, the proxy watches this directory for kubelet
	// projections and hot-reloads the upstream client cert without a
	// pod restart. When empty, hot-reload is disabled; rotation still
	// works via the legacy pod-template-annotation restart.
	CertDir string
	// RenewInterval is how often the auto-renewer wakes up to check the
	// live cert's remaining validity. Negative disables auto-renewal
	// entirely (useful in tests and audited environments where rotation
	// must be operator-driven). Zero falls back to DefaultRenewInterval.
	RenewInterval time.Duration
	// RenewThreshold is the remaining-validity window below which the
	// renewer issues a fresh cert. Zero falls back to DefaultRenewThreshold.
	RenewThreshold time.Duration
}

// Option is a function that configures the APIServiceProxy.
type Option func(*Options)

// WithProjectID sets the project ID for the APIServiceProxy.
func WithProjectID(id string) Option {
	return func(o *Options) {
		if pID, err := uuid.Parse(id); err == nil {
			o.ProjectID = pID
		} else {
			log.Errorf("failed to parse project ID: %v", err)
		}
	}
}

// WithNamespace sets the namespace for the APIServiceProxy.
func WithNamespace(ns string) Option {
	return func(o *Options) {
		o.Namespace = ns
	}
}

// WithServiceName sets the Kubernetes Service name for the aggregated API endpoint.
func WithServiceName(name string) Option {
	return func(o *Options) {
		o.ServiceName = name
	}
}

// WithClusterName sets the cluster name for the APIServiceProxy.
func WithClusterName(name string) Option {
	return func(o *Options) {
		o.ClusterName = name
	}
}

// WithToken sets the token for the APIServiceProxy.
func WithToken(token string) Option {
	return func(o *Options) {
		o.Token = token
	}
}

// WithKubeconfigPath sets the kubeconfig path for the APIServiceProxy.
func WithKubeconfigPath(path string) Option {
	return func(o *Options) {
		o.KubeconfigPath = path
	}
}

// WithAPIHost sets the Apoxy Cloud API host for certificate issuance.
func WithAPIHost(host string) Option {
	return func(o *Options) {
		o.APIHost = host
	}
}

// WithLocalMode enables local-mode TLS handling: outbound HTTPS to cosmos
// and the apiserver proxy skips certificate verification, since the dev
// cluster uses cert-manager self-signed certs that aren't in the pod trust
// store. Never set this in production.
func WithLocalMode(local bool) Option {
	return func(o *Options) {
		o.LocalMode = local
	}
}

// WithCertDir sets the directory the upstream client cert is mounted at.
// When non-empty, the proxy watches this dir for kubelet Secret-projection
// updates and hot-reloads the cert without a pod restart.
func WithCertDir(dir string) Option {
	return func(o *Options) {
		o.CertDir = dir
	}
}

// WithRenewInterval sets how often the auto-renewer checks the live cert.
// A negative duration disables auto-renewal.
func WithRenewInterval(d time.Duration) Option {
	return func(o *Options) {
		o.RenewInterval = d
	}
}

// WithRenewThreshold sets the remaining-validity window below which the
// renewer issues a fresh cert.
func WithRenewThreshold(d time.Duration) Option {
	return func(o *Options) {
		o.RenewThreshold = d
	}
}
