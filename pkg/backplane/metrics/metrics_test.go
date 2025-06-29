package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
		"/metrics":           strings.TrimPrefix(metricsServer.URL, "http://") + "/metrics",
		"/stats/prometheus":  strings.TrimPrefix(statsServer.URL, "http://") + "/stats/prometheus",
		"/nonexistent/path":  "localhost:9999/nonexistent",
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
