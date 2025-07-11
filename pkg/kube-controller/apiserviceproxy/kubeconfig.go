package apiserviceproxy

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func (p *APIServiceProxy) configureKubeconfigProxy(ctx context.Context) error {
	log.Printf("configuring kubeconfig proxy from %s", p.opts.KubeconfigPath)

	cfg, err := clientcmd.BuildConfigFromFlags("", p.opts.KubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	hostURL, err := url.Parse(cfg.Host)
	if err != nil {
		return fmt.Errorf("failed to parse host from kubeconfig: %w", err)
	}

	transport, err := rest.TransportFor(cfg)
	if err != nil {
		return fmt.Errorf("failed to create transport: %w", err)
	}

	p.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = hostURL.Scheme
			req.URL.Host = hostURL.Host
			req.Host = hostURL.Host
		},
		Transport: transport,
	}

	return nil
}
