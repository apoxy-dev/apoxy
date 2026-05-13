package apiserviceproxy

import (
	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/pkg/log"
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
