package metrics

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"

	metricsv1alpha1 "github.com/apoxy-dev/apoxy/api/metrics/v1alpha1"
)

// recordingResponder captures what the connect handler wrote, standing in for
// the apiserver's content-negotiating responder.
type recordingResponder struct {
	obj  runtime.Object
	code int
	err  error
}

func (r *recordingResponder) Object(code int, obj runtime.Object) {
	r.code, r.obj = code, obj
}

func (r *recordingResponder) Error(err error) { r.err = err }

type fakeRecipes struct {
	rec Recipe
	err error
}

func (f fakeRecipes) Recipe(context.Context, string) (Recipe, error) {
	if f.err != nil {
		return Recipe{}, f.err
	}
	return f.rec, nil
}

type fakeSeries struct {
	calls int
	err   error
}

func (f *fakeSeries) ReadSeries(_ context.Context, req *SeriesRequest) (*metricsv1alpha1.MetricSeriesSet, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &metricsv1alpha1.MetricSeriesSet{Metric: req.Metric, Series: []metricsv1alpha1.MetricSeries{}}, nil
}

type fakeOwners struct{ exists bool }

func (f fakeOwners) OwnerExists(context.Context, Scope) (bool, error) { return f.exists, nil }

func serve(t *testing.T, c *SeriesConnecter, target string) (*recordingResponder, *httptest.ResponseRecorder) {
	t.Helper()
	resp := &recordingResponder{}
	h, err := c.Connect(context.Background(), "http.requests", nil, resp)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return resp, w
}

func TestSeriesConnecter(t *testing.T) {
	target := "/apis/metrics.apoxy.dev/v1alpha1/metrics/http.requests/series?scopeKind=Gateway&scopeName=prod&step=5m"

	t.Run("no backend configured is 501", func(t *testing.T) {
		c := NewSeriesConnecter(SeriesOptions{
			Recipes:      fakeRecipes{rec: testRecipe()},
			MissingFlags: []string{"--clickhouse_addr"},
			Now:          func() time.Time { return now },
			Log:          quietLogger(),
		})
		resp, _ := serve(t, c, target)
		if got := statusOf(t, resp.err); got != http.StatusNotImplemented {
			t.Fatalf("code = %d, want 501", got)
		}
		if !strings.Contains(resp.err.Error(), "--clickhouse_addr") {
			t.Errorf("the 501 does not name the missing flag: %v", resp.err)
		}
	})

	t.Run("a missing owner is 404 before the backend is read", func(t *testing.T) {
		reader := &fakeSeries{}
		c := NewSeriesConnecter(SeriesOptions{
			Reader:  reader,
			Recipes: fakeRecipes{rec: testRecipe()},
			Owners:  fakeOwners{exists: false},
			Now:     func() time.Time { return now },
			Log:     quietLogger(),
		})
		resp, _ := serve(t, c, target)
		if got := statusOf(t, resp.err); got != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", got)
		}
		if reader.calls != 0 {
			t.Errorf("the backend was read %d times for a missing owner", reader.calls)
		}
	})

	t.Run("an unreachable backend is 503", func(t *testing.T) {
		c := NewSeriesConnecter(SeriesOptions{
			Reader:  &fakeSeries{err: Unavailable(errors.New("connection refused"))},
			Recipes: fakeRecipes{rec: testRecipe()},
			Owners:  fakeOwners{exists: true},
			Now:     func() time.Time { return now },
			Log:     quietLogger(),
		})
		resp, _ := serve(t, c, target)
		if got := statusOf(t, resp.err); got != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want 503", got)
		}
		if strings.Contains(resp.err.Error(), "connection refused") {
			t.Errorf("the 503 leaks the backend message: %v", resp.err)
		}
	})

	t.Run("a second read is served from the cache with a max-age", func(t *testing.T) {
		reader := &fakeSeries{}
		c := NewSeriesConnecter(SeriesOptions{
			Reader:  reader,
			Recipes: fakeRecipes{rec: testRecipe()},
			Owners:  fakeOwners{exists: true},
			Cache:   NewCache(DefaultCacheTTL),
			Now:     func() time.Time { return now },
			Log:     quietLogger(),
		})
		resp, w := serve(t, c, target)
		if resp.err != nil {
			t.Fatalf("first read failed: %v", resp.err)
		}
		if got := w.Header().Get("Cache-Control"); got != "max-age=60" {
			t.Errorf("Cache-Control = %q, want max-age=60", got)
		}
		if _, w2 := serve(t, c, target); w2.Header().Get("Cache-Control") == "" {
			t.Error("the cached read carries no Cache-Control")
		}
		if reader.calls != 1 {
			t.Errorf("the backend was read %d times, want 1", reader.calls)
		}
	})
}

// quietLogger keeps the expected failure paths out of the test output.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got none")
	}
	var statusErr *apierrors.StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("error is not a Status: %T", err)
	}
	return int(statusErr.ErrStatus.Code)
}

// TestFailLogLevel checks that a rejected request is logged at Info and only
// a server fault is logged at Error, so client mistakes do not page anyone.
func TestFailLogLevel(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want slog.Level
	}{
		{name: "bad request", err: BadRequest("nope"), want: slog.LevelInfo},
		{name: "not found", err: NotFound(metricsv1alpha1.Resource("metrics"), "nosuch"), want: slog.LevelInfo},
		{name: "internal", err: Internal(errors.New("boom")), want: slog.LevelError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got slog.Level
			var seen bool
			h := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})
			log := slog.New(levelRecorder{Handler: h, got: &got, seen: &seen})
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			fail(log, &recordingResponder{}, req, "series", tc.err)
			if !seen {
				t.Fatal("no log record")
			}
			if got != tc.want {
				t.Fatalf("level = %v, want %v", got, tc.want)
			}
		})
	}
}

// levelRecorder remembers the level of the last record it handled.
type levelRecorder struct {
	slog.Handler
	got  *slog.Level
	seen *bool
}

func (l levelRecorder) Handle(ctx context.Context, r slog.Record) error {
	*l.got, *l.seen = r.Level, true
	return l.Handler.Handle(ctx, r)
}

// fakeSnapshots stands in for the read model behind a snapshot connecter,
// counting reads so a cache hit is visible.
type fakeSnapshots struct {
	calls int
	err   error
}

func (f *fakeSnapshots) ReadSnapshot(context.Context, *SnapshotRequest) (runtime.Object, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &metricsv1alpha1.ProxyMetrics{}, nil
}

func serveSnapshot(t *testing.T, c *SnapshotConnecter, target string) (*recordingResponder, *httptest.ResponseRecorder) {
	t.Helper()
	resp := &recordingResponder{}
	h, err := c.Connect(context.Background(), "proxy-1", nil, resp)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return resp, w
}

// connectedOf reads the decorated gauge back off a snapshot response.
func connectedOf(t *testing.T, obj runtime.Object) int32 {
	t.Helper()
	snap, ok := obj.(*metricsv1alpha1.ProxyMetrics)
	if !ok {
		t.Fatalf("response is %T, want *ProxyMetrics", obj)
	}
	return snap.Replicas.Connected
}

// TestSnapshotConnecterDecorate checks the decorator seam: it runs on a fresh
// read, the cached object carries the decoration without a second call, and a
// decorator failure maps through the same error path as a backend failure.
func TestSnapshotConnecterDecorate(t *testing.T) {
	target := "/apis/core.apoxy.dev/v1alpha2/proxies/proxy-1/metrics?window=1h"

	t.Run("a fresh read is decorated", func(t *testing.T) {
		reader := &fakeSnapshots{}
		var decorated int
		c := NewSnapshotConnecter(SnapshotOptions{
			Kind:   SnapshotProxy,
			Reader: reader,
			Decorate: func(_ context.Context, req *SnapshotRequest, obj runtime.Object) error {
				decorated++
				if req.Name != "proxy-1" {
					t.Errorf("decorator saw owner %q, want proxy-1", req.Name)
				}
				obj.(*metricsv1alpha1.ProxyMetrics).Replicas.Connected = 3
				return nil
			},
			Owners: fakeOwners{exists: true},
			Now:    func() time.Time { return now },
			Log:    quietLogger(),
		})
		resp, _ := serveSnapshot(t, c, target)
		if resp.err != nil {
			t.Fatalf("read failed: %v", resp.err)
		}
		if got := connectedOf(t, resp.obj); got != 3 {
			t.Errorf("replicas.connected = %d, want 3", got)
		}
		if decorated != 1 {
			t.Errorf("the decorator ran %d times, want 1", decorated)
		}
	})

	t.Run("a cached read still carries the decoration", func(t *testing.T) {
		reader := &fakeSnapshots{}
		var decorated int
		c := NewSnapshotConnecter(SnapshotOptions{
			Kind:   SnapshotProxy,
			Reader: reader,
			Decorate: func(_ context.Context, _ *SnapshotRequest, obj runtime.Object) error {
				decorated++
				obj.(*metricsv1alpha1.ProxyMetrics).Replicas.Connected = 3
				return nil
			},
			Owners: fakeOwners{exists: true},
			Cache:  NewCache(DefaultCacheTTL),
			Now:    func() time.Time { return now },
			Log:    quietLogger(),
		})
		if resp, _ := serveSnapshot(t, c, target); resp.err != nil {
			t.Fatalf("first read failed: %v", resp.err)
		}
		resp, _ := serveSnapshot(t, c, target)
		if resp.err != nil {
			t.Fatalf("second read failed: %v", resp.err)
		}
		// The decoration is on the cached object, so the second read serves it
		// without running the decorator again.
		if got := connectedOf(t, resp.obj); got != 3 {
			t.Errorf("cached replicas.connected = %d, want 3", got)
		}
		if reader.calls != 1 {
			t.Errorf("the backend was read %d times, want 1", reader.calls)
		}
		if decorated != 1 {
			t.Errorf("the decorator ran %d times, want 1", decorated)
		}
	})

	t.Run("a decorator failure is mapped and nothing is cached", func(t *testing.T) {
		reader := &fakeSnapshots{}
		cache := NewCache(DefaultCacheTTL)
		c := NewSnapshotConnecter(SnapshotOptions{
			Kind:   SnapshotProxy,
			Reader: reader,
			Decorate: func(context.Context, *SnapshotRequest, runtime.Object) error {
				return Unavailable(errors.New("owner status unreadable"))
			},
			Owners: fakeOwners{exists: true},
			Cache:  cache,
			Now:    func() time.Time { return now },
			Log:    quietLogger(),
		})
		resp, _ := serveSnapshot(t, c, target)
		if got := statusOf(t, resp.err); got != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want 503", got)
		}
		if strings.Contains(resp.err.Error(), "owner status unreadable") {
			t.Errorf("the 503 leaks the decorator message: %v", resp.err)
		}
		// A failed decoration must not leave an undecorated object behind, so
		// the next read goes back to the backend.
		serveSnapshot(t, c, target)
		if reader.calls != 2 {
			t.Errorf("the backend was read %d times, want 2; a failed read was cached", reader.calls)
		}
	})

	t.Run("a nil decorator is a no-op", func(t *testing.T) {
		c := NewSnapshotConnecter(SnapshotOptions{
			Kind:   SnapshotProxy,
			Reader: &fakeSnapshots{},
			Owners: fakeOwners{exists: true},
			Now:    func() time.Time { return now },
			Log:    quietLogger(),
		})
		resp, _ := serveSnapshot(t, c, target)
		if resp.err != nil {
			t.Fatalf("read failed: %v", resp.err)
		}
		if got := connectedOf(t, resp.obj); got != 0 {
			t.Errorf("replicas.connected = %d, want 0", got)
		}
	})
}
