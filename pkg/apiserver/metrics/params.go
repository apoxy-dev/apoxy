package metrics

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Caps shared by the snapshot connecters and metrics/<name>/series. A request
// over a cap is a 400 that names the factors, so the caller can lower top,
// widen step, or ask for fewer measures.
const (
	// DefaultWindow is the window both surfaces read when the caller gives
	// none, so a KPI tile and the chart under it cover the same range.
	DefaultWindow = time.Hour

	// MaxBuckets bounds the time axis of one series read.
	MaxBuckets = 1500

	// MaxSeries bounds the cardinality axis. Rows past it set truncated.
	MaxSeries = 50

	// MaxPoints bounds buckets x series x measures for one response.
	MaxPoints = 20000

	// MaxLookback bounds how far back a raw-log read may start.
	MaxLookback = 31 * 24 * time.Hour

	// MaxRawGroupByWindow bounds a grouped read over raw logs, which scans
	// rows rather than buckets.
	MaxRawGroupByWindow = 24 * time.Hour
)

// Source is the table a recipe reads. Granularity is both the bucket width and
// the minimum step: a smaller step is rounded up rather than rejected.
type Source struct {
	// Name is the source name a recipe writes in spec.source.
	Name string
	// Granularity is the bucket width. It is one second for raw logs, which
	// have no bucket of their own.
	Granularity time.Duration
	// MaxWindow is the widest window this source serves.
	MaxWindow time.Duration
	// Raw is true for a source of individual log rows, which is bounded by the
	// concurrency cap and by MaxRawGroupByWindow rather than by bucket count.
	Raw bool
}

// The Phase 1 sources. A recipe has exactly one source, resolved once on
// write, and is never routed per request.
var (
	// SourceOTELLogs is the raw access-log table.
	SourceOTELLogs = Source{Name: "otel_logs", Granularity: time.Second, MaxWindow: MaxLookback, Raw: true}
	// SourceHTTP1m is the one-minute rollup.
	SourceHTTP1m = Source{Name: "http_1m", Granularity: time.Minute, MaxWindow: 7 * 24 * time.Hour}
	// SourceHTTP1h is the one-hour rollup.
	SourceHTTP1h = Source{Name: "http_1h", Granularity: time.Hour, MaxWindow: 400 * 24 * time.Hour}
	// SourceEnvoy1m is the one-minute Envoy stats rollup.
	SourceEnvoy1m = Source{Name: "envoy_1m", Granularity: time.Minute, MaxWindow: 30 * 24 * time.Hour}
	// SourceRelay1m is the one-minute tunnel datapath rollup, written by the
	// relay.
	SourceRelay1m = Source{Name: "relay_1m", Granularity: time.Minute, MaxWindow: 30 * 24 * time.Hour}
)

var sources = map[string]Source{
	SourceOTELLogs.Name: SourceOTELLogs,
	SourceHTTP1m.Name:   SourceHTTP1m,
	SourceHTTP1h.Name:   SourceHTTP1h,
	SourceEnvoy1m.Name:  SourceEnvoy1m,
	SourceRelay1m.Name:  SourceRelay1m,
}

// LookupSource resolves a source name.
func LookupSource(name string) (Source, bool) {
	s, ok := sources[name]
	return s, ok
}

// SourceNames lists the known sources, for an error message.
func SourceNames() []string {
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ScopeKind is an owner kind a scope parameter accepts. It takes an object
// kind, not a resource name.
type ScopeKind string

const (
	// ScopeProject is the whole project. It takes no scope name.
	ScopeProject ScopeKind = "Project"
	// ScopeGateway scopes to one Gateway.
	ScopeGateway ScopeKind = "Gateway"
	// ScopeHTTPRoute scopes to one HTTPRoute.
	ScopeHTTPRoute ScopeKind = "HTTPRoute"
	// ScopeProxy scopes to one Proxy.
	ScopeProxy ScopeKind = "Proxy"
	// ScopeService scopes to one compute Service.
	ScopeService ScopeKind = "Service"
	// ScopeVPCNetwork scopes to one VPCNetwork.
	ScopeVPCNetwork ScopeKind = "VPCNetwork"
	// ScopeTunnel scopes to one Tunnel, which is one agent connection to a
	// relay.
	ScopeTunnel ScopeKind = "Tunnel"
)

// ValidScopeKinds is the list a 400 message prints and MetricSource publishes
// in status.scopes, so a client does not discover it by trial.
var ValidScopeKinds = []ScopeKind{
	ScopeProject, ScopeGateway, ScopeHTTPRoute, ScopeProxy, ScopeService, ScopeVPCNetwork,
	ScopeTunnel,
}

func validScopeKind(k ScopeKind) bool {
	for _, v := range ValidScopeKinds {
		if v == k {
			return true
		}
	}
	return false
}

func scopeKindNames() string {
	names := make([]string, len(ValidScopeKinds))
	for i, k := range ValidScopeKinds {
		names[i] = string(k)
	}
	return strings.Join(names, ", ")
}

// Scope is the server-enforced read scope. Every field comes from the request
// path or from the scope parameters, never from a client-supplied predicate.
type Scope struct {
	// Kind is the owner kind. Project means the whole project.
	Kind ScopeKind
	// Name is the owner name. It is empty for a Project scope.
	Name string
	// Listener narrows a Gateway scope to one listener.
	Listener string
}

// Recipe is the compiled fact set the validator needs about a Metric: the
// resolved source, the groupable keys, the measure names, and the columns a
// client shows first. The deployment that owns the catalog fills it in.
type Recipe struct {
	// Name is the recipe name.
	Name string
	// Source is the resolved source.
	Source Source
	// Keys are the valid groupBy values, from MetricSource.
	Keys []string
	// Measures are the recipe's output columns.
	Measures []string
	// DefaultColumns are the measures a client shows first. The first entry is
	// the default orderBy.
	DefaultColumns []string
	// Units maps a measure name to its display unit, echoed in a response.
	Units map[string]string
	// Compiled reports whether the recipe still compiles. A recipe that does
	// not is a 422 from series.
	Compiled bool
	// CompileMessage is the sanitized reason a recipe does not compile.
	CompileMessage string
}

// SeriesRequest is a parsed, validated series query. The read model builds its
// statement from this and from nothing else in the request.
type SeriesRequest struct {
	// Metric is the recipe name.
	Metric string
	// Recipe is the compiled recipe the request resolved to.
	Recipe Recipe
	// Scope is the server-enforced read scope.
	Scope Scope
	// GroupBy is one role: key field of the source, or empty.
	GroupBy string
	// OrderBy is the measure the top-N ranks by.
	OrderBy string
	// Top bounds the series count.
	Top int
	// Since and Until are the half-open [since, until) window bounds.
	Since time.Time
	Until time.Time
	// Step is the applied bucket width, rounded up to the source granularity.
	Step time.Duration
	// Buckets is how many buckets the window yields at Step.
	Buckets int
	// DataUpTo is the end of the last complete bucket.
	DataUpTo time.Time
}

// SnapshotKind is one of the per-owner snapshot kinds.
type SnapshotKind string

const (
	// SnapshotGateway is returned by gateways/<name>/metrics.
	SnapshotGateway SnapshotKind = "GatewayMetrics"
	// SnapshotHTTPRoute is returned by httproutes/<name>/metrics.
	SnapshotHTTPRoute SnapshotKind = "HTTPRouteMetrics"
	// SnapshotProxy is returned by proxies/<name>/metrics.
	SnapshotProxy SnapshotKind = "ProxyMetrics"
	// SnapshotService is returned by services/<name>/metrics.
	SnapshotService SnapshotKind = "ServiceMetrics"
	// SnapshotVPCNetwork is returned by vpcnetworks/<name>/metrics.
	SnapshotVPCNetwork SnapshotKind = "VPCNetworkMetrics"
	// SnapshotTunnel is returned by tunnels/<name>/metrics.
	SnapshotTunnel SnapshotKind = "TunnelMetrics"
)

// includeTokens enumerates the legal include tokens per kind. An unknown token
// is a 400.
var includeTokens = map[SnapshotKind][]string{
	SnapshotGateway:    {"routes"},
	SnapshotHTTPRoute:  {"rules", "backends"},
	SnapshotProxy:      nil,
	SnapshotService:    {"revisions"},
	SnapshotVPCNetwork: {"services", "tunnels"},
	SnapshotTunnel:     nil,
}

// snapshotScopeKinds maps a snapshot kind to the owner scope it reads with.
var snapshotScopeKinds = map[SnapshotKind]ScopeKind{
	SnapshotGateway:    ScopeGateway,
	SnapshotHTTPRoute:  ScopeHTTPRoute,
	SnapshotProxy:      ScopeProxy,
	SnapshotService:    ScopeService,
	SnapshotVPCNetwork: ScopeVPCNetwork,
	SnapshotTunnel:     ScopeTunnel,
}

// IncludeTokens lists the legal include tokens for a snapshot kind.
func IncludeTokens(k SnapshotKind) []string { return includeTokens[k] }

// SnapshotRequest is a parsed, validated snapshot read.
type SnapshotRequest struct {
	// Kind is the snapshot kind the connecter serves.
	Kind SnapshotKind
	// Name is the owner name from the request path.
	Name string
	// Scope is the owner scope, derived from the path.
	Scope Scope
	// Since and Until are the half-open [since, until) window bounds.
	Since time.Time
	Until time.Time
	// Window is Until minus Since.
	Window time.Duration
	// DataUpTo is the end of the last complete bucket.
	DataUpTo time.Time
	// Granularity is the source bucket width. A snapshot has no step of its
	// own, so this is the unit the response cache aligns the window to and the
	// max-age the response advertises.
	Granularity time.Duration
	// Include are the resolved nesting tokens, already expanded from all.
	Include []string
	// Top bounds each cut leaf list.
	Top int
	// OrderBy is the measure the leaf list ranks by.
	OrderBy string
	// Metrics restricts the recipes evaluated. An empty list means every
	// managed recipe.
	Metrics []string
}

// Includes reports whether token was requested.
func (r *SnapshotRequest) Includes(token string) bool {
	for _, t := range r.Include {
		if t == token {
			return true
		}
	}
	return false
}

// dayPattern matches a whole-day duration such as 7d or -400d. Go durations
// stop at hours, but every window cap in the design is stated in days and a
// console range selector offers them, so a day suffix is accepted and
// converted before the standard parser runs.
var dayPattern = regexp.MustCompile(`^([-+]?[0-9]+(?:\.[0-9]+)?)d$`)

// ParseDuration parses a Go duration, also accepting a whole-day suffix.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if m := dayPattern.FindStringSubmatch(s); m != nil {
		days, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(s)
}

// ParseInstant parses an RFC3339 instant or a relative duration such as -6h.
// A relative value is resolved against now.
func ParseInstant(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, BadRequest("time value is empty")
	}
	if s[0] == '-' || s[0] == '+' {
		d, err := ParseDuration(s)
		if err != nil {
			return time.Time{}, BadRequest("invalid time %q: want an RFC3339 instant or a relative duration such as -6h or -7d", s)
		}
		return now.Add(d).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, BadRequest("invalid time %q: want an RFC3339 instant or a relative duration such as -6h or -7d", s)
	}
	return t.UTC(), nil
}

// Window is the resolved read window plus the end of the last complete bucket.
type Window struct {
	Since    time.Time
	Until    time.Time
	DataUpTo time.Time
}

// ParseWindow resolves since, until, and window against the source
// granularity. window is sugar for since=-<d> and is rejected together with
// since. until defaults to the end of the last complete bucket, which is what
// lets a client tell a partial trailing bucket from a drop in traffic.
func ParseWindow(q url.Values, src Source, maxWindow time.Duration, now time.Time) (Window, error) {
	var w Window

	gran := src.Granularity
	if gran <= 0 {
		gran = time.Second
	}
	dataUpTo := now.UTC().Truncate(gran)
	w.DataUpTo = dataUpTo

	rawSince := strings.TrimSpace(q.Get("since"))
	rawUntil := strings.TrimSpace(q.Get("until"))
	rawWindow := strings.TrimSpace(q.Get("window"))

	if rawWindow != "" && rawSince != "" {
		return w, BadRequest("window and since are mutually exclusive; window is sugar for since=-<duration>")
	}

	until := dataUpTo
	if rawUntil != "" {
		t, err := ParseInstant(rawUntil, now)
		if err != nil {
			return w, err
		}
		until = t
	}
	// Clamp a future until to the last complete bucket: there is no data past
	// it, and the response echoes the effective value, so the clamp is visible.
	if until.After(dataUpTo) {
		until = dataUpTo
	}

	var since time.Time
	switch {
	case rawWindow != "":
		d, err := ParseDuration(rawWindow)
		if err != nil || d <= 0 {
			return w, BadRequest("invalid window %q: want a positive duration such as 24h or 7d", rawWindow)
		}
		since = until.Add(-d)
	case rawSince != "":
		t, err := ParseInstant(rawSince, now)
		if err != nil {
			return w, err
		}
		since = t
	default:
		since = until.Add(-DefaultWindow)
	}

	if !until.After(since) {
		return w, BadRequest("until must be after since")
	}

	limit := maxWindow
	if limit <= 0 || (src.MaxWindow > 0 && src.MaxWindow < limit) {
		limit = src.MaxWindow
	}
	if limit > 0 && until.Sub(since) > limit {
		return w, BadRequest("window %s exceeds the %s maximum for source %s; narrow since and until",
			until.Sub(since), limit, src.Name)
	}

	w.Since, w.Until = since.UTC(), until.UTC()
	return w, nil
}

// ParseStep parses an explicit step and rounds it up to the source
// granularity. An empty step returns zero, which means the caller must pick
// DefaultStep.
func ParseStep(raw string, src Source) (time.Duration, error) {
	gran := src.Granularity
	if gran <= 0 {
		gran = time.Second
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	step, err := ParseDuration(raw)
	if err != nil {
		return 0, BadRequest("invalid step %q: want a duration such as 5m", raw)
	}
	if step <= 0 {
		return 0, BadRequest("step must be positive")
	}
	// Round up rather than reject: the applied step is echoed, so the caller
	// sees what it got.
	if rem := step % gran; rem != 0 {
		step += gran - rem
	}
	return step, nil
}

// DefaultStep is the source granularity, widened in whole granularity steps
// until the window fits under the bucket cap. A caller that gives no step gets
// the finest chart the caps allow rather than a 400.
func DefaultStep(since, until time.Time, src Source) time.Duration {
	gran := src.Granularity
	if gran <= 0 {
		gran = time.Second
	}
	step := gran
	if n := bucketCount(since, until, step); n > MaxBuckets {
		mult := int64((n + MaxBuckets - 1) / MaxBuckets)
		step = gran * time.Duration(mult)
		for bucketCount(since, until, step) > MaxBuckets {
			step += gran
		}
	}
	return step
}

// bucketCount is how many buckets a window yields at step, counting the
// trailing partial bucket.
func bucketCount(since, until time.Time, step time.Duration) int {
	return int((until.Sub(since) + step - 1) / step)
}

// ParseScope resolves the scope parameters. Project takes no name; every other
// kind requires one. A listener narrows a Gateway scope only.
func ParseScope(q url.Values) (Scope, error) {
	var s Scope
	kind := ScopeKind(strings.TrimSpace(q.Get("scopeKind")))
	name := strings.TrimSpace(q.Get("scopeName"))
	listener := strings.TrimSpace(q.Get("scopeListener"))

	if kind == "" {
		kind = ScopeProject
	}
	if !validScopeKind(kind) {
		return s, BadRequest("invalid scopeKind %q: want one of %s", kind, scopeKindNames())
	}
	if kind == ScopeProject {
		if name != "" {
			return s, BadRequest("scopeName is not valid with scopeKind=Project, which is the whole project")
		}
	} else if name == "" {
		return s, BadRequest("scopeName is required with scopeKind=%s", kind)
	}
	// The name reaches the statement as a bound parameter, which carries no
	// shape rule of its own. Every owner object is named by the apiserver, so
	// hold the parameter to the same DNS-1123 rule.
	if name != "" {
		if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
			return s, BadRequest("invalid scopeName %q: %s", name, errs[0])
		}
	}
	if listener != "" {
		if kind != ScopeGateway {
			return s, BadRequest("scopeListener is valid only with scopeKind=Gateway")
		}
		if errs := validation.IsDNS1123Subdomain(listener); len(errs) > 0 {
			return s, BadRequest("invalid scopeListener %q: %s", listener, errs[0])
		}
	}

	s.Kind, s.Name, s.Listener = kind, name, listener
	return s, nil
}

// ParseSeriesRequest validates a series query against the recipe it names. The
// recipe is resolved by the caller, because the catalog lives in the
// deployment that owns the read model.
func ParseSeriesRequest(q url.Values, rec Recipe, now time.Time) (*SeriesRequest, error) {
	if !rec.Compiled {
		msg := rec.CompileMessage
		if msg == "" {
			msg = "the recipe does not compile against the current schema"
		}
		return nil, Unprocessable("metric %q cannot be evaluated: %s", rec.Name, msg)
	}

	req := &SeriesRequest{Metric: rec.Name, Recipe: rec}

	scope, err := ParseScope(q)
	if err != nil {
		return nil, err
	}
	req.Scope = scope

	if gb := strings.TrimSpace(q.Get("groupBy")); gb != "" {
		if !contains(rec.Keys, gb) {
			return nil, BadRequest("metric %q cannot be grouped by %q: valid keys are %s",
				rec.Name, gb, strings.Join(rec.Keys, ", "))
		}
		req.GroupBy = gb
	}

	orderBy, err := resolveOrderBy(q.Get("orderBy"), rec)
	if err != nil {
		return nil, err
	}
	req.OrderBy = orderBy

	top, err := parseTop(q.Get("top"))
	if err != nil {
		return nil, err
	}
	req.Top = top

	// A grouped read over raw rows scans log records rather than buckets, so
	// it takes the tighter window cap.
	maxWindow := rec.Source.MaxWindow
	if rec.Source.Raw && req.GroupBy != "" {
		maxWindow = MaxRawGroupByWindow
	}
	w, err := ParseWindow(q, rec.Source, maxWindow, now)
	if err != nil {
		return nil, err
	}
	req.Since, req.Until, req.DataUpTo = w.Since, w.Until, w.DataUpTo

	step, err := ParseStep(q.Get("step"), rec.Source)
	if err != nil {
		return nil, err
	}
	if step == 0 {
		step = DefaultStep(req.Since, req.Until, rec.Source)
	}
	req.Step = step

	buckets := bucketCount(req.Since, req.Until, step)
	if buckets > MaxBuckets {
		return nil, BadRequest("window %s at step %s yields %d buckets, over the %d cap; widen step or narrow the window",
			req.Until.Sub(req.Since), step, buckets, MaxBuckets)
	}
	req.Buckets = buckets

	series := 1
	if req.GroupBy != "" {
		series = top
	}
	measures := len(rec.Measures)
	if measures == 0 {
		measures = 1
	}
	if points := buckets * series * measures; points > MaxPoints {
		return nil, BadRequest(
			"%d buckets x %d series x %d measures is %d points, over the %d cap; lower top, widen step, or ask for fewer measures",
			buckets, series, measures, points, MaxPoints)
	}

	return req, nil
}

// ParseSnapshotRequest validates a snapshot read. The owner scope comes from
// the request path, so no scope parameter is accepted.
func ParseSnapshotRequest(q url.Values, kind SnapshotKind, name string, src Source, now time.Time) (*SnapshotRequest, error) {
	scopeKind, ok := snapshotScopeKinds[kind]
	if !ok {
		return nil, Internal(BadRequest("unknown snapshot kind %q", kind))
	}
	if strings.TrimSpace(name) == "" {
		return nil, BadRequest("the owner name is required in the request path")
	}

	req := &SnapshotRequest{
		Kind:  kind,
		Name:  name,
		Scope: Scope{Kind: scopeKind, Name: name},
	}

	if listener := strings.TrimSpace(q.Get("scopeListener")); listener != "" {
		if scopeKind != ScopeGateway {
			return nil, BadRequest("scopeListener is valid only on a Gateway snapshot")
		}
		if errs := validation.IsDNS1123Subdomain(listener); len(errs) > 0 {
			return nil, BadRequest("invalid scopeListener %q: %s", listener, errs[0])
		}
		req.Scope.Listener = listener
	}
	// The path already fixes the scope, so a scope parameter is a misleading
	// no-op rather than a refinement.
	if q.Get("scopeKind") != "" || q.Get("scopeName") != "" {
		return nil, BadRequest("scopeKind and scopeName are not valid on a snapshot; the path already fixes the scope")
	}

	w, err := ParseWindow(q, src, src.MaxWindow, now)
	if err != nil {
		return nil, err
	}
	req.Since, req.Until, req.DataUpTo = w.Since, w.Until, w.DataUpTo
	req.Window = req.Until.Sub(req.Since)
	req.Granularity = src.Granularity

	include, err := parseInclude(q["include"], kind)
	if err != nil {
		return nil, err
	}
	req.Include = include

	top, err := parseTop(q.Get("top"))
	if err != nil {
		return nil, err
	}
	req.Top = top

	if ob := strings.TrimSpace(q.Get("orderBy")); ob != "" {
		req.OrderBy = ob
	}

	// metric repeats; it does not take a comma-separated list.
	for _, m := range q["metric"] {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		req.Metrics = append(req.Metrics, m)
	}

	return req, nil
}

// parseInclude resolves the include tokens for a kind, expanding all.
func parseInclude(raw []string, kind SnapshotKind) ([]string, error) {
	valid := includeTokens[kind]
	var out []string
	seen := map[string]bool{}
	for _, entry := range raw {
		for _, tok := range strings.Split(entry, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if tok == "all" {
				for _, v := range valid {
					if !seen[v] {
						seen[v] = true
						out = append(out, v)
					}
				}
				continue
			}
			if !contains(valid, tok) {
				if len(valid) == 0 {
					return nil, BadRequest("%s takes no include token", kind)
				}
				return nil, BadRequest("invalid include token %q for %s: valid tokens are %s, or all",
					tok, kind, strings.Join(valid, ", "))
			}
			if !seen[tok] {
				seen[tok] = true
				out = append(out, tok)
			}
		}
	}
	return out, nil
}

// parseTop bounds a leaf list or a series set. An absent top is the cap.
func parseTop(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return MaxSeries, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, BadRequest("invalid top %q: want a positive integer up to %d", raw, MaxSeries)
	}
	if n > MaxSeries {
		return 0, BadRequest("top %d is over the %d cap", n, MaxSeries)
	}
	return n, nil
}

// resolveOrderBy defaults the ranking measure to the recipe's first default
// column, which is what keeps a top-by-errors breakdown on the server.
func resolveOrderBy(raw string, rec Recipe) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if len(rec.DefaultColumns) > 0 {
			return rec.DefaultColumns[0], nil
		}
		if len(rec.Measures) > 0 {
			return rec.Measures[0], nil
		}
		return "", nil
	}
	if len(rec.Measures) > 0 && !contains(rec.Measures, raw) {
		return "", BadRequest("metric %q cannot be ordered by %q: valid measures are %s",
			rec.Name, raw, strings.Join(rec.Measures, ", "))
	}
	return raw, nil
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}
