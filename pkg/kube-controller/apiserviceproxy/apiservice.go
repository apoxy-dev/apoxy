package apiserviceproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
)

const (
	DefaultPort = 8443
)

// APIServiceProxy is a proxy for the Apoxy API.
type APIServiceProxy struct {
	kC   kubernetes.Interface
	opts *Options

	proxy    *httputil.ReverseProxy
	cert     tls.Certificate
	certPool *x509.CertPool
}

// NewAPIServiceProxy creates a new APIServiceProxy with the given options.
func NewAPIServiceProxy(
	ctx context.Context,
	kC kubernetes.Interface,
	opts ...Option,
) (*APIServiceProxy, error) {
	o := &Options{}
	for _, opt := range opts {
		opt(o)
	}

	p := &APIServiceProxy{
		kC:   kC,
		opts: o,
	}

	if o.ProjectID != uuid.Nil && o.Token != "" {
		if err := p.configureCloudProxy(ctx); err != nil {
			return nil, fmt.Errorf("failed to configure cloud proxy: %w", err)
		}
	} else if o.KubeconfigPath != "" {
		if err := p.configureKubeconfigProxy(ctx); err != nil {
			return nil, fmt.Errorf("failed to configure kubeconfig proxy: %w", err)
		}
	} else {
		return nil, fmt.Errorf("either project ID and token or kubeconfig path must be provided")
	}

	return p, nil
}

// Run starts the APIServiceProxy.
// It listens on a unix socket and proxies requests to the Apoxy API.
func (p *APIServiceProxy) Run(ctx context.Context) error {
	log.Printf("starting api service proxy")

	s := &http.Server{
		Addr:    fmt.Sprintf(":%d", DefaultPort),
		Handler: p.proxy,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{p.cert},
			ClientCAs:    p.certPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
	}

	return s.ListenAndServeTLS("", "")
}
