// Package metrics provides an HTTP handler for proxying metrics requests
// to specific upstream endpoints using net/http/httputil.ReverseProxy.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// ProxyHandler is an HTTP handler that proxies requests to specific upstream endpoints.
type ProxyHandler struct {
	// upstreams maps request paths to upstream URLs.
	upstreams map[string]string
	// proxies maps request paths to ReverseProxy instances.
	proxies map[string]*httputil.ReverseProxy
}

// NewProxyHandler creates a new ProxyHandler with the given upstreams configuration.
// The upstreams map keys are request paths and values are upstream URLs.
// For example: {"/metrics": "127.0.0.1:8000/metrics", "/stats/prometheus": "127.0.0.1:19000/stats/prometheus"}
func NewProxyHandler(upstreams map[string]string) *ProxyHandler {
	handler := &ProxyHandler{
		upstreams: upstreams,
		proxies:   make(map[string]*httputil.ReverseProxy),
	}

	// Initialize reverse proxies for each upstream
	for path, upstreamURL := range upstreams {
		// Ensure the upstream URL has a scheme
		if !strings.HasPrefix(upstreamURL, "http://") && !strings.HasPrefix(upstreamURL, "https://") {
			upstreamURL = "http://" + upstreamURL
		}

		// Parse the upstream URL
		target, err := url.Parse(upstreamURL)
		if err != nil {
			log.Errorf("Invalid upstream URL for path %s: %v", path, err)
			continue
		}

		// Create a reverse proxy for this upstream
		proxy := httputil.NewSingleHostReverseProxy(target)

		// Customize the director to handle path rewriting if needed
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.URL.Path = target.Path
			req.URL.RawPath = target.RawPath
		}

		// Add error handling
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Errorf("Error proxying request to %s: %v", target.String(), err)
			http.Error(w, fmt.Sprintf("failed to proxy request: %v", err), http.StatusBadGateway)
		}

		// Set a reasonable timeout for the transport
		proxy.Transport = &http.Transport{
			ResponseHeaderTimeout: 10 * time.Second,
		}

		handler.proxies[path] = proxy
	}

	return handler
}

// ServeHTTP implements the http.Handler interface.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Find the matching proxy for the requested path
	proxy, ok := h.proxies[path]
	if !ok {
		http.Error(w, fmt.Sprintf("no upstream configured for path: %s", path), http.StatusNotFound)
		return
	}

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

// StartServer starts an HTTP server on the specified port with the given ProxyHandler.
func StartServer(ctx context.Context, port int, handler *ProxyHandler) error {
	server := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: handler,
	}

	// Start the server in a goroutine
	go func() {
		log.Infof("Starting metrics proxy server on port %d", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Metrics proxy server failed: %v", err)
		}
	}()

	// Wait for context cancellation to shut down the server
	go func() {
		<-ctx.Done()
		log.Infof("Shutting down metrics proxy server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Errorf("Failed to gracefully shut down metrics proxy server: %v", err)
		}
	}()

	return nil
}
