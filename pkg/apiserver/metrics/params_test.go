package metrics

import (
	"math"
	"net/url"
	"strings"
	"testing"
	"time"
)

// now is a fixed anchor on a whole hour, so a truncation to any supported
// granularity is a no-op and every expected instant is easy to read.
var now = time.Date(2026, 8, 20, 21, 0, 30, 0, time.UTC)

// testRecipe is the http.requests built-in, which every parser case reads.
func testRecipe() Recipe {
	return Recipe{
		Name:           "http.requests",
		Source:         SourceHTTP1m,
		Keys:           []string{"gateway", "listener", "route", "status_class", "method"},
		Measures:       []string{"total", "status_4xx", "status_5xx"},
		DefaultColumns: []string{"total", "status_5xx"},
		Compiled:       true,
	}
}

func values(pairs ...string) url.Values {
	q := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		q.Add(pairs[i], pairs[i+1])
	}
	return q
}

func TestParseSeriesRequest(t *testing.T) {
	cases := []struct {
		name    string
		query   url.Values
		recipe  func(Recipe) Recipe
		wantErr string
		check   func(t *testing.T, r *SeriesRequest)
	}{
		{
			name:  "defaults",
			query: values(),
			check: func(t *testing.T, r *SeriesRequest) {
				if r.Scope.Kind != ScopeProject {
					t.Errorf("scope kind = %q, want Project", r.Scope.Kind)
				}
				if got := r.Until.Sub(r.Since); got != DefaultWindow {
					t.Errorf("window = %s, want %s", got, DefaultWindow)
				}
				if r.Step != time.Minute {
					t.Errorf("step = %s, want 1m", r.Step)
				}
				if r.OrderBy != "total" {
					t.Errorf("orderBy = %q, want total", r.OrderBy)
				}
				if r.Top != MaxSeries {
					t.Errorf("top = %d, want %d", r.Top, MaxSeries)
				}
			},
		},
		{
			name:  "scoped gateway with groupBy",
			query: values("scopeKind", "Gateway", "scopeName", "prod", "groupBy", "route", "since", "-6h", "step", "5m", "top", "10", "orderBy", "status_5xx"),
			check: func(t *testing.T, r *SeriesRequest) {
				if r.Scope.Name != "prod" || r.Scope.Kind != ScopeGateway {
					t.Errorf("scope = %+v", r.Scope)
				}
				if r.GroupBy != "route" || r.OrderBy != "status_5xx" || r.Top != 10 {
					t.Errorf("request = %+v", r)
				}
				if r.Step != 5*time.Minute || r.Buckets != 72 {
					t.Errorf("step = %s buckets = %d, want 5m / 72", r.Step, r.Buckets)
				}
			},
		},
		{
			name:  "step rounds up to granularity and is echoed",
			query: values("step", "10s"),
			check: func(t *testing.T, r *SeriesRequest) {
				if r.Step != time.Minute {
					t.Errorf("step = %s, want 1m", r.Step)
				}
			},
		},
		{
			name:  "step rounds up to the next whole granularity",
			query: values("step", "90s"),
			check: func(t *testing.T, r *SeriesRequest) {
				if r.Step != 2*time.Minute {
					t.Errorf("step = %s, want 2m", r.Step)
				}
			},
		},
		{
			name:    "unknown scopeKind lists the valid kinds",
			query:   values("scopeKind", "Widget", "scopeName", "x"),
			wantErr: "want one of Project, Gateway",
		},
		{
			name:    "scopeName required for a named kind",
			query:   values("scopeKind", "Gateway"),
			wantErr: "scopeName is required",
		},
		{
			name:    "scopeName rejected for Project",
			query:   values("scopeKind", "Project", "scopeName", "prod"),
			wantErr: "not valid with scopeKind=Project",
		},
		{
			name:    "scopeListener needs a Gateway scope",
			query:   values("scopeKind", "HTTPRoute", "scopeName", "api", "scopeListener", "https"),
			wantErr: "valid only with scopeKind=Gateway",
		},
		{
			name:    "unknown groupBy lists the valid keys",
			query:   values("groupBy", "url.path"),
			wantErr: "valid keys are gateway, listener, route, status_class, method",
		},
		{
			name:    "unknown orderBy lists the valid measures",
			query:   values("orderBy", "nope"),
			wantErr: "valid measures are total, status_4xx, status_5xx",
		},
		{
			name:    "top over the cap",
			query:   values("top", "500"),
			wantErr: "over the 50 cap",
		},
		{
			name:    "bucket cap",
			query:   values("since", "-48h", "step", "1m"),
			wantErr: "over the 1500 cap",
		},
		{
			name:    "point cap names the three factors",
			query:   values("since", "-24h", "step", "1m", "groupBy", "route", "top", "50"),
			wantErr: "measures is 216000 points, over the 20000 cap",
		},
		{
			name:    "window cap on the 1m rollup",
			query:   values("since", "-8d"),
			wantErr: "exceeds the 168h0m0s maximum for source http_1m",
		},
		{
			name:   "window cap on the 1h rollup allows 400d",
			query:  values("since", "-300d"),
			recipe: func(r Recipe) Recipe { r.Source = SourceHTTP1h; return r },
			check: func(t *testing.T, r *SeriesRequest) {
				if r.Step < time.Hour {
					t.Errorf("step = %s, want at least 1h", r.Step)
				}
				if r.Buckets > MaxBuckets {
					t.Errorf("buckets = %d, over the cap", r.Buckets)
				}
			},
		},
		{
			name:    "raw groupBy is capped at 24h",
			query:   values("groupBy", "url.path", "since", "-48h"),
			recipe:  func(r Recipe) Recipe { r.Source = SourceOTELLogs; r.Keys = []string{"url.path"}; return r },
			wantErr: "exceeds the 24h0m0s maximum for source otel_logs",
		},
		{
			name:   "raw without groupBy keeps the 31d lookback",
			query:  values("since", "-48h"),
			recipe: func(r Recipe) Recipe { r.Source = SourceOTELLogs; return r },
			check: func(t *testing.T, r *SeriesRequest) {
				if r.Buckets > MaxBuckets {
					t.Errorf("buckets = %d, over the cap", r.Buckets)
				}
			},
		},
		{
			name:    "a recipe that does not compile is unprocessable",
			query:   values(),
			recipe:  func(r Recipe) Recipe { r.Compiled = false; r.CompileMessage = "unknown field foo"; return r },
			wantErr: "unknown field foo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := testRecipe()
			if tc.recipe != nil {
				rec = tc.recipe(rec)
			}
			got, err := ParseSeriesRequest(tc.query, rec, now)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want an error containing %q, got none", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestParseWindow(t *testing.T) {
	cases := []struct {
		name      string
		query     url.Values
		src       Source
		wantErr   string
		wantSince time.Time
		wantUntil time.Time
	}{
		{
			name:      "until defaults to the last complete bucket",
			query:     values(),
			src:       SourceHTTP1m,
			wantSince: now.Truncate(time.Minute).Add(-DefaultWindow),
			wantUntil: now.Truncate(time.Minute),
		},
		{
			name:      "window is sugar for a relative since",
			query:     values("window", "24h"),
			src:       SourceHTTP1m,
			wantSince: now.Truncate(time.Minute).Add(-24 * time.Hour),
			wantUntil: now.Truncate(time.Minute),
		},
		{
			name:    "window and since are mutually exclusive",
			query:   values("window", "24h", "since", "-1h"),
			src:     SourceHTTP1m,
			wantErr: "mutually exclusive",
		},
		{
			name:      "RFC3339 bounds pass through",
			query:     values("since", "2026-08-20T15:00:00Z", "until", "2026-08-20T18:00:00Z"),
			src:       SourceHTTP1m,
			wantSince: time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC),
			wantUntil: time.Date(2026, 8, 20, 18, 0, 0, 0, time.UTC),
		},
		{
			name:      "a future until is clamped to the last complete bucket",
			query:     values("until", "2027-01-01T00:00:00Z"),
			src:       SourceHTTP1m,
			wantSince: now.Truncate(time.Minute).Add(-DefaultWindow),
			wantUntil: now.Truncate(time.Minute),
		},
		{
			name:    "until must be after since",
			query:   values("since", "2026-08-20T18:00:00Z", "until", "2026-08-20T15:00:00Z"),
			src:     SourceHTTP1m,
			wantErr: "until must be after since",
		},
		{
			name:    "a malformed instant names both accepted forms",
			query:   values("since", "yesterday"),
			src:     SourceHTTP1m,
			wantErr: "want an RFC3339 instant or a relative duration",
		},
		{
			name:      "the 1h rollup buckets to the hour",
			query:     values(),
			src:       SourceHTTP1h,
			wantSince: now.Truncate(time.Hour).Add(-DefaultWindow),
			wantUntil: now.Truncate(time.Hour),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := ParseWindow(tc.query, tc.src, tc.src.MaxWindow, now)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !w.Since.Equal(tc.wantSince) {
				t.Errorf("since = %s, want %s", w.Since, tc.wantSince)
			}
			if !w.Until.Equal(tc.wantUntil) {
				t.Errorf("until = %s, want %s", w.Until, tc.wantUntil)
			}
			if !w.DataUpTo.Equal(now.Truncate(tc.src.Granularity)) {
				t.Errorf("dataUpTo = %s, want the last complete bucket", w.DataUpTo)
			}
		})
	}
}

func TestParseSnapshotRequest(t *testing.T) {
	cases := []struct {
		name    string
		kind    SnapshotKind
		owner   string
		query   url.Values
		wantErr string
		check   func(t *testing.T, r *SnapshotRequest)
	}{
		{
			name:  "gateway defaults to no routes",
			kind:  SnapshotGateway,
			owner: "prod",
			query: values(),
			check: func(t *testing.T, r *SnapshotRequest) {
				if len(r.Include) != 0 {
					t.Errorf("include = %v, want none", r.Include)
				}
				if r.Scope.Kind != ScopeGateway || r.Scope.Name != "prod" {
					t.Errorf("scope = %+v", r.Scope)
				}
				if r.Window != DefaultWindow {
					t.Errorf("window = %s, want %s", r.Window, DefaultWindow)
				}
			},
		},
		{
			name:  "include all expands to every token for the kind",
			kind:  SnapshotHTTPRoute,
			owner: "api",
			query: values("include", "all"),
			check: func(t *testing.T, r *SnapshotRequest) {
				if len(r.Include) != 2 || r.Include[0] != "rules" || r.Include[1] != "backends" {
					t.Errorf("include = %v, want [rules backends]", r.Include)
				}
			},
		},
		{
			name:  "metric repeats",
			kind:  SnapshotGateway,
			owner: "prod",
			query: values("metric", "http.requests", "metric", "http.latency"),
			check: func(t *testing.T, r *SnapshotRequest) {
				if len(r.Metrics) != 2 {
					t.Errorf("metrics = %v, want two entries", r.Metrics)
				}
			},
		},
		{
			name:    "unknown include token lists the valid ones",
			kind:    SnapshotGateway,
			owner:   "prod",
			query:   values("include", "backends"),
			wantErr: "valid tokens are routes, or all",
		},
		{
			name:    "a kind with no nesting takes no token",
			kind:    SnapshotProxy,
			owner:   "default",
			query:   values("include", "routes"),
			wantErr: "takes no include token",
		},
		{
			name:    "a scope parameter is rejected on a snapshot",
			kind:    SnapshotGateway,
			owner:   "prod",
			query:   values("scopeName", "other"),
			wantErr: "the path already fixes the scope",
		},
		{
			name:    "the window cap applies to a snapshot too",
			kind:    SnapshotGateway,
			owner:   "prod",
			query:   values("window", "30d"),
			wantErr: "maximum for source http_1m",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSnapshotRequest(tc.query, tc.kind, tc.owner, SourceHTTP1m, now)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestRoundLatencyMillis(t *testing.T) {
	cases := []struct {
		name string
		in   float64
		want float64
	}{
		{name: "rounds up", in: 411.6, want: 412},
		{name: "rounds down", in: 411.4, want: 411},
		{name: "whole value is unchanged", in: 412, want: 412},
		{name: "an empty bucket collapses to zero", in: math.NaN(), want: 0},
		{name: "an infinite value collapses to zero", in: math.Inf(1), want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RoundLatencyMillis(tc.in); got != tc.want {
				t.Fatalf("RoundLatencyMillis(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
