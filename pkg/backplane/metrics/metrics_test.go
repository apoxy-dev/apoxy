package metrics

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestProxyHandler(t *testing.T) {
	// Create mock upstream servers
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("metrics data"))
	}))
	defer metricsServer.Close()

	statsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stats/prometheus" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("prometheus stats"))
	}))
	defer statsServer.Close()

	// Configure upstreams without the "http://" prefix to test that it gets added
	upstreams := map[string]string{
		"/metrics":          strings.TrimPrefix(metricsServer.URL, "http://") + "/metrics",
		"/stats/prometheus": strings.TrimPrefix(statsServer.URL, "http://") + "/stats/prometheus",
		"/nonexistent/path": "localhost:9999/nonexistent",
	}

	handler := NewProxyHandler(upstreams)

	// Test successful proxy to /metrics
	t.Run("Proxy to /metrics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost:8888/metrics", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}
		if string(body) != "metrics data" {
			t.Errorf("Expected body 'metrics data', got '%s'", string(body))
		}
		if resp.Header.Get("Content-Type") != "text/plain" {
			t.Errorf("Expected Content-Type 'text/plain', got '%s'", resp.Header.Get("Content-Type"))
		}
	})

	// Test successful proxy to /stats/prometheus
	t.Run("Proxy to /stats/prometheus", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost:8888/stats/prometheus", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}
		if string(body) != "prometheus stats" {
			t.Errorf("Expected body 'prometheus stats', got '%s'", string(body))
		}
	})

	// Test path not configured
	t.Run("Path not configured", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost:8888/unknown", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status NotFound, got %v", resp.StatusCode)
		}
	})
}

func TestStartServer(t *testing.T) {
	upstreams := map[string]string{
		"/metrics": "localhost:8000/metrics",
	}
	handler := NewProxyHandler(upstreams)

	// Create a context that will be canceled after a short time
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start the server
	err := StartServer(ctx, 0, handler) // Use port 0 to let the OS choose an available port
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Wait for the context to be canceled
	<-ctx.Done()
	// Give the server a moment to shut down
	time.Sleep(200 * time.Millisecond)

	// No assertions needed here, we're just testing that the server starts and stops without errors
}

// testGatherer returns one backplane family with a fixed value.
func testGatherer(t *testing.T) prometheus.Gatherer {
	t.Helper()

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "apoxy_backplane_envoy_up",
		Help: "One while the Envoy process runs.",
	}))

	return reg
}

func TestProxyHandlerAppendsGatherer(t *testing.T) {
	const envoyBody = "envoy_server_live 1"

	cases := []struct {
		name        string
		upstream    func(w http.ResponseWriter, r *http.Request)
		unreachable bool
		path        string
		wantStatus  int
		wantBody    []string
		missingBody []string
	}{
		{
			name: "upstream answers",
			upstream: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(envoyBody))
			},
			path:       "/envoy/metrics",
			wantStatus: http.StatusOK,
			wantBody:   []string{envoyBody, "apoxy_backplane_envoy_up 0"},
		},
		{
			name: "upstream fails",
			upstream: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "no stats", http.StatusBadGateway)
			},
			path:        "/envoy/metrics",
			wantStatus:  http.StatusOK,
			wantBody:    []string{"apoxy_backplane_envoy_up 0"},
			missingBody: []string{envoyBody, "no stats"},
		},
		{
			name:        "upstream is unreachable",
			unreachable: true,
			path:        "/envoy/metrics",
			wantStatus:  http.StatusOK,
			wantBody:    []string{"apoxy_backplane_envoy_up 0"},
		},
		{
			name: "metrics path serves the gatherer alone",
			upstream: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(envoyBody))
			},
			path:        "/metrics",
			wantStatus:  http.StatusOK,
			wantBody:    []string{"apoxy_backplane_envoy_up 0"},
			missingBody: []string{envoyBody},
		},
		{
			name: "unknown path is not found",
			upstream: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(envoyBody))
			},
			path:       "/unknown",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := "127.0.0.1:1/stats/prometheus"
			if !tc.unreachable {
				srv := httptest.NewServer(http.HandlerFunc(tc.upstream))
				defer srv.Close()
				upstream = strings.TrimPrefix(srv.URL, "http://") + "/stats/prometheus"
			}

			g := testGatherer(t)
			handler := NewProxyHandler(
				map[string]string{"/envoy/metrics": upstream},
				WithAppendGatherer("/envoy/metrics", g),
				WithHandler("/metrics", promhttp.HandlerFor(g, promhttp.HandlerOpts{})),
			)

			req := httptest.NewRequest("GET", "http://localhost:8888"+tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read the response: %v", err)
			}

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
			}
			for _, want := range tc.wantBody {
				if !strings.Contains(string(body), want) {
					t.Errorf("expected the body to hold %q, got %q", want, string(body))
				}
			}
			for _, missing := range tc.missingBody {
				if strings.Contains(string(body), missing) {
					t.Errorf("expected the body to leave out %q, got %q", missing, string(body))
				}
			}
		})
	}
}

func TestProxyHandlerKeepsEnvoyBodyFirst(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("envoy_server_live 1\n"))
	}))
	defer srv.Close()

	handler := NewProxyHandler(
		map[string]string{"/envoy/metrics": strings.TrimPrefix(srv.URL, "http://") + "/stats/prometheus"},
		WithAppendGatherer("/envoy/metrics", testGatherer(t)),
	)

	req := httptest.NewRequest("GET", "http://localhost:8888/envoy/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body := w.Body.String()
	envoyAt := strings.Index(body, "envoy_server_live")
	backplaneAt := strings.Index(body, "apoxy_backplane_envoy_up")
	if envoyAt < 0 || backplaneAt < 0 || envoyAt > backplaneAt {
		t.Fatalf("expected the Envoy body first, got %q", body)
	}
}

func TestProxyHandlerAsksForAPlainUpstreamBody(t *testing.T) {
	const body = "envoy_server_live 1\n"

	// The upstream compresses whenever the request accepts it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gz.Write([]byte(body))
	}))
	defer srv.Close()

	handler := NewProxyHandler(
		map[string]string{"/envoy/metrics": strings.TrimPrefix(srv.URL, "http://") + "/stats/prometheus"},
		WithAppendGatherer("/envoy/metrics", testGatherer(t)),
	)

	req := httptest.NewRequest("GET", "http://localhost:8888/envoy/metrics", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("expected a plain response, got Content-Encoding %q", w.Header().Get("Content-Encoding"))
	}
	if !strings.Contains(w.Body.String(), body) {
		t.Fatalf("expected the plain Envoy body, got %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "apoxy_backplane_envoy_up") {
		t.Fatalf("expected the backplane families, got %q", w.Body.String())
	}
	if req.Header.Get("Accept-Encoding") != "gzip" {
		t.Fatalf("expected the request of the caller to keep its header, got %q", req.Header.Get("Accept-Encoding"))
	}
}
