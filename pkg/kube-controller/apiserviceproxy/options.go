package apiserviceproxy

import (
	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// Options contains the configuration for the APIServiceProxy.
type Options struct {
	ProjectID      uuid.UUID
	Namespace      string
	ClusterName    string
	Token          string
	KubeconfigPath string
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
