// Package metrics provides an HTTP handler for proxying metrics requests
// to specific upstream endpoints using net/http/httputil.ReverseProxy.
package metrics

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// ProxyHandler is an HTTP handler that proxies requests to specific upstream endpoints.
// upstreamHeaderTimeout bounds the wait for the first byte from a metrics upstream.
const upstreamHeaderTimeout = 3 * time.Second

type ProxyHandler struct {
	// upstreams maps request paths to upstream URLs.
	upstreams map[string]string
	// proxies maps request paths to ReverseProxy instances.
	proxies map[string]*httputil.ReverseProxy
	// handlers maps request paths to handlers that answer without an upstream.
	handlers map[string]http.Handler
	// appendPath is the path whose response carries the families of
	// appendGatherer after the upstream body.
	appendPath string
	// appendGatherer holds the metrics the backplane owns.
	appendGatherer prometheus.Gatherer
}

// Option configures a ProxyHandler.
type Option func(*ProxyHandler)

// WithAppendGatherer writes the families of g after the upstream body on path.
// The upstream is the Envoy admin interface, which does not answer while Envoy
// restarts. The response then carries only the families of g, so that a scrape
// still reports whether Envoy runs.
func WithAppendGatherer(path string, g prometheus.Gatherer) Option {
	return func(h *ProxyHandler) {
		h.appendPath = path
		h.appendGatherer = g
	}
}

// WithHandler answers path with handler instead of proxying it.
func WithHandler(path string, handler http.Handler) Option {
	return func(h *ProxyHandler) {
		h.handlers[path] = handler
	}
}

// NewProxyHandler creates a new ProxyHandler with the given upstreams configuration.
// The upstreams map keys are request paths and values are upstream URLs.
// For example: {"/metrics": "127.0.0.1:8000/metrics", "/stats/prometheus": "127.0.0.1:19000/stats/prometheus"}
func NewProxyHandler(upstreams map[string]string, opts ...Option) *ProxyHandler {
	handler := &ProxyHandler{
		upstreams: upstreams,
		proxies:   make(map[string]*httputil.ReverseProxy),
		handlers:  make(map[string]http.Handler),
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

		// A stalled Envoy admin port must not hold the scrape past the
		// default Prometheus scrape timeout of 10 s.
		proxy.Transport = &http.Transport{
			ResponseHeaderTimeout: upstreamHeaderTimeout,
		}

		handler.proxies[path] = proxy
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(handler)
	}

	return handler
}

// ServeHTTP implements the http.Handler interface.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if handler, ok := h.handlers[path]; ok {
		handler.ServeHTTP(w, r)
		return
	}

	// Find the matching proxy for the requested path
	proxy, ok := h.proxies[path]

	if h.appendGatherer != nil && path == h.appendPath {
		h.serveWithGatherer(w, r, proxy)
		return
	}

	if !ok {
		http.Error(w, fmt.Sprintf("no upstream configured for path: %s", path), http.StatusNotFound)
		return
	}

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

// serveWithGatherer writes the upstream body and then the families of the
// gatherer. The family names of the two sources are disjoint, so the result is
// valid exposition text.
func (h *ProxyHandler) serveWithGatherer(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	var upstream bytes.Buffer
	status := http.StatusBadGateway
	if proxy != nil {
		// The body is concatenated with text, so the upstream must not
		// compress it.
		plain := r.Clone(r.Context())
		plain.Header.Del("Accept-Encoding")

		rec := &bufferedResponse{header: make(http.Header), body: &upstream}
		proxy.ServeHTTP(rec, plain)
		status = rec.status
	}

	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	w.Header().Set("Content-Type", string(format))
	w.WriteHeader(http.StatusOK)

	if status == http.StatusOK && upstream.Len() > 0 {
		body := upstream.Bytes()
		w.Write(body)
		// Every exposition line ends with a newline. Envoy may leave the last
		// one out.
		if body[len(body)-1] != '\n' {
			w.Write([]byte("\n"))
		}
	}

	families, err := h.appendGatherer.Gather()
	if err != nil {
		log.Errorf("Failed to gather the backplane metrics: %v", err)
	}
	enc := expfmt.NewEncoder(w, format)
	for _, mf := range families {
		if err := enc.Encode(mf); err != nil {
			log.Errorf("Failed to write the backplane metrics: %v", err)
			return
		}
	}
}

// bufferedResponse collects an upstream response so that the handler can drop
// it when the upstream fails.
type bufferedResponse struct {
	header http.Header
	body   *bytes.Buffer
	status int
}

// Header implements the http.ResponseWriter interface.
func (b *bufferedResponse) Header() http.Header { return b.header }

// Write implements the http.ResponseWriter interface.
func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

// WriteHeader implements the http.ResponseWriter interface.
func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
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
