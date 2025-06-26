// Package metrics provides an HTTP handler for proxying metrics requests
// to specific upstream endpoints.
package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// ProxyHandler is an HTTP handler that proxies requests to specific upstream endpoints.
type ProxyHandler struct {
	// upstreams maps request paths to upstream URLs.
	upstreams map[string]string
	// client is the HTTP client used to make requests to upstream endpoints.
	client *http.Client
}

// NewProxyHandler creates a new ProxyHandler with the given upstreams configuration.
// The upstreams map keys are request paths and values are upstream URLs.
// For example: {"/metrics": "127.0.0.1:8000/metrics", "/stats/prometheus": "127.0.0.1:19000/stats/prometheus"}
func NewProxyHandler(upstreams map[string]string) *ProxyHandler {
	return &ProxyHandler{
		upstreams: upstreams,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ServeHTTP implements the http.Handler interface.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Find the matching upstream for the requested path
	upstreamURL, ok := h.upstreams[path]
	if !ok {
		http.Error(w, fmt.Sprintf("no upstream configured for path: %s", path), http.StatusNotFound)
		return
	}

	// Ensure the upstream URL has a scheme
	if !strings.HasPrefix(upstreamURL, "http://") && !strings.HasPrefix(upstreamURL, "https://") {
		upstreamURL = "http://" + upstreamURL
	}

	// Parse the upstream URL
	u, err := url.Parse(upstreamURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid upstream URL: %v", err), http.StatusInternalServerError)
		return
	}

	// Create a new request to the upstream
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create upstream request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers from the original request
	for key, values := range r.Header {
		for _, value := range values {
			upstreamReq.Header.Add(key, value)
		}
	}

	// Make the request to the upstream
	resp, err := h.client.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to proxy request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy the response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set the status code
	w.WriteHeader(resp.StatusCode)

	// Copy the response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Errorf("Failed to copy response body: %v", err)
	}
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
