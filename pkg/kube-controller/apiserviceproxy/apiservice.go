package apiserviceproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"time"

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

	proxy              *httputil.ReverseProxy
	servingCert        tls.Certificate
	upstreamClientCert tls.Certificate
	upstreamRootCAs    *x509.CertPool
	caBundle           []byte
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

// CABundle returns the CA bundle for the APIServiceProxy.
func (p *APIServiceProxy) CABundle() []byte {
	return p.caBundle
}

// Run starts the APIServiceProxy.
// It listens on a unix socket and proxies requests to the Apoxy API.
func (p *APIServiceProxy) Run(ctx context.Context) error {
	log.Printf("starting api service proxy")
	if len(p.servingCert.Certificate) == 0 {
		return fmt.Errorf("serving certificate is not configured")
	}

	s := &http.Server{
		Addr:    fmt.Sprintf(":%d", DefaultPort),
		Handler: p.proxy,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{p.servingCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("failed to shut down api service proxy: %v", err)
		}
	}()

	if err := s.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
