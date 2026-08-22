package metrics

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/maypok86/otter/v2"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	// DefaultCacheTTL is how long a metrics response stays cached. It matches
	// the granularity of the live rollup, so a poll that arrives before the
	// next bucket closes cannot see anything new anyway.
	DefaultCacheTTL = time.Minute

	// defaultCacheEntries bounds the cache. A metrics response holds up to
	// MaxPoints values, so the cache must not grow without a bound.
	defaultCacheEntries = 128
)

// Cache is the in-memory response cache the connecters share. The key aligns
// the window to the step before it is built, so two polls a few seconds apart
// produce the same key and the second one is served without a second scan.
//
// Entries expire a TTL after they are written and the cache is bounded by
// entry count.
type Cache struct {
	ttl     time.Duration
	entries *otter.Cache[string, runtime.Object]
}

// NewCache returns a cache with the given TTL. A TTL of zero or less takes
// DefaultCacheTTL.
func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{
		ttl: ttl,
		entries: otter.Must(&otter.Options[string, runtime.Object]{
			MaximumSize:      defaultCacheEntries,
			ExpiryCalculator: otter.ExpiryWriting[string, runtime.Object](ttl),
		}),
	}
}

// TTL is how long an entry stays valid. It is also the max-age a response
// advertises.
func (c *Cache) TTL() time.Duration {
	if c == nil {
		return 0
	}
	return c.ttl
}

// Get returns a deep copy of the cached response, so a caller that mutates the
// result cannot corrupt the entry.
func (c *Cache) Get(key string) (runtime.Object, bool) {
	if c == nil {
		return nil, false
	}
	obj, ok := c.entries.GetIfPresent(key)
	if !ok {
		return nil, false
	}
	return obj.DeepCopyObject(), true
}

// Put stores a deep copy of obj under key.
func (c *Cache) Put(key string, obj runtime.Object) {
	if c == nil || obj == nil {
		return
	}
	c.entries.Set(key, obj.DeepCopyObject())
}

// AlignDown truncates t down to a whole multiple of step, in UTC. Zero or a
// negative step leaves t alone.
func AlignDown(t time.Time, step time.Duration) time.Time {
	if step <= 0 {
		return t.UTC()
	}
	return t.UTC().Truncate(step)
}

// SeriesCacheKey builds the cache key for a parsed series read. The window is
// aligned to the applied step, and the step itself is part of the key, so two
// reads at different steps never share an entry.
func SeriesCacheKey(req *SeriesRequest) string {
	var b strings.Builder
	b.WriteString("series|")
	b.WriteString(req.Metric)
	b.WriteByte('|')
	b.WriteString(string(req.Scope.Kind))
	b.WriteByte('|')
	b.WriteString(req.Scope.Name)
	b.WriteByte('|')
	b.WriteString(req.Scope.Listener)
	b.WriteByte('|')
	b.WriteString(req.GroupBy)
	b.WriteByte('|')
	b.WriteString(req.OrderBy)
	b.WriteByte('|')
	fmt.Fprintf(&b, "top=%d|step=%s|", req.Top, req.Step)
	writeWindow(&b, req.Since, req.Until, req.Step)
	return b.String()
}

// SnapshotCacheKey builds the cache key for a parsed snapshot read. A snapshot
// has no step, so the window aligns to the source granularity.
func SnapshotCacheKey(req *SnapshotRequest) string {
	var b strings.Builder
	b.WriteString("snapshot|")
	b.WriteString(string(req.Kind))
	b.WriteByte('|')
	b.WriteString(req.Name)
	b.WriteByte('|')
	b.WriteString(req.Scope.Listener)
	b.WriteByte('|')
	b.WriteString(strings.Join(req.Include, ","))
	b.WriteByte('|')
	metrics := append([]string(nil), req.Metrics...)
	sort.Strings(metrics)
	b.WriteString(strings.Join(metrics, ","))
	b.WriteByte('|')
	fmt.Fprintf(&b, "top=%d|orderBy=%s|", req.Top, req.OrderBy)
	writeWindow(&b, req.Since, req.Until, req.Granularity)
	return b.String()
}

func writeWindow(b *strings.Builder, since, until time.Time, align time.Duration) {
	fmt.Fprintf(b, "since=%d|until=%d",
		AlignDown(since, align).Unix(), AlignDown(until, align).Unix())
}
