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
