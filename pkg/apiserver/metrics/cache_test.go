package metrics

import (
	"net/url"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	metricsv1alpha1 "github.com/apoxy-dev/apoxy/api/metrics/v1alpha1"
)

// TestSeriesCacheKeyAlignment covers the design's caching rule: window bounds
// are aligned to step before the key is built, so two polls a few seconds
// apart share one entry, and a different step never does.
func TestSeriesCacheKeyAlignment(t *testing.T) {
	base := now

	cases := []struct {
		name     string
		firstAt  time.Time
		secondAt time.Time
		first    url.Values
		second   url.Values
		wantSame bool
	}{
		{
			name:     "two reads seconds apart hit",
			firstAt:  base,
			secondAt: base.Add(7 * time.Second),
			first:    values("scopeKind", "Gateway", "scopeName", "prod", "step", "5m"),
			second:   values("scopeKind", "Gateway", "scopeName", "prod", "step", "5m"),
			wantSame: true,
		},
		{
			name:     "a different step misses",
			firstAt:  base,
			secondAt: base,
			first:    values("step", "5m"),
			second:   values("step", "10m"),
			wantSame: false,
		},
		{
			name:     "a different scope misses",
			firstAt:  base,
			secondAt: base,
			first:    values("scopeKind", "Gateway", "scopeName", "prod", "step", "5m"),
			second:   values("scopeKind", "Gateway", "scopeName", "staging", "step", "5m"),
			wantSame: false,
		},
		{
			name:     "a different groupBy misses",
			firstAt:  base,
			secondAt: base,
			first:    values("groupBy", "route", "step", "5m"),
			second:   values("groupBy", "gateway", "step", "5m"),
			wantSame: false,
		},
		{
			name:     "a read in the next step bucket misses",
			firstAt:  base,
			secondAt: base.Add(5 * time.Minute),
			first:    values("step", "5m"),
			second:   values("step", "5m"),
			wantSame: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseSeriesRequest(tc.first, testRecipe(), tc.firstAt)
			if err != nil {
				t.Fatalf("first parse: %v", err)
			}
			b, err := ParseSeriesRequest(tc.second, testRecipe(), tc.secondAt)
			if err != nil {
				t.Fatalf("second parse: %v", err)
			}
			ka, kb := SeriesCacheKey(a), SeriesCacheKey(b)
			if same := ka == kb; same != tc.wantSame {
				t.Fatalf("keys equal = %v, want %v\n a: %s\n b: %s", same, tc.wantSame, ka, kb)
			}
		})
	}
}

func TestSnapshotCacheKeyAlignment(t *testing.T) {
	a, err := ParseSnapshotRequest(values("window", "24h"), SnapshotGateway, "prod", SourceHTTP1m, now)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	b, err := ParseSnapshotRequest(values("window", "24h"), SnapshotGateway, "prod", SourceHTTP1m, now.Add(9*time.Second))
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if SnapshotCacheKey(a) != SnapshotCacheKey(b) {
		t.Errorf("two polls in one bucket miss:\n a: %s\n b: %s", SnapshotCacheKey(a), SnapshotCacheKey(b))
	}

	c, err := ParseSnapshotRequest(values("window", "24h", "include", "routes"), SnapshotGateway, "prod", SourceHTTP1m, now)
	if err != nil {
		t.Fatalf("third parse: %v", err)
	}
	if SnapshotCacheKey(a) == SnapshotCacheKey(c) {
		t.Errorf("include=routes shares a key with the default read")
	}
}

func TestCacheGetPut(t *testing.T) {
	const ttl = 30 * time.Millisecond
	c := NewCache(ttl)

	set := &metricsv1alpha1.MetricSeriesSet{
		Metric: "http.requests",
		Series: []metricsv1alpha1.MetricSeries{{
			Labels: map[string]string{"route": "api"},
			Points: []metricsv1alpha1.MetricPoint{{
				Timestamp: metav1.NewTime(now),
				Values:    metricsv1alpha1.Measures{"total": 5210},
			}},
		}},
	}

	if _, ok := c.Get("k"); ok {
		t.Fatal("an empty cache returned an entry")
	}
	c.Put("k", set)

	got, ok := c.Get("k")
	if !ok {
		t.Fatal("the entry was not cached")
	}
	cached, ok := got.(*metricsv1alpha1.MetricSeriesSet)
	if !ok {
		t.Fatalf("cached object is %T", got)
	}
	// The cache must hand out a copy: a handler that mutates the result must
	// not corrupt the entry.
	cached.Series[0].Points[0].Values["total"] = 0
	again, _ := c.Get("k")
	if again.(*metricsv1alpha1.MetricSeriesSet).Series[0].Points[0].Values["total"] != 5210 {
		t.Error("mutating a returned object changed the cached entry")
	}

	time.Sleep(2 * ttl)
	if _, ok := c.Get("k"); ok {
		t.Error("an expired entry was served")
	}
}
