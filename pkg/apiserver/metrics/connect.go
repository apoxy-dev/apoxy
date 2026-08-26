package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/generic"
	registryrest "k8s.io/apiserver/pkg/registry/rest"

	metricsv1alpha1 "github.com/apoxy-dev/apoxy/api/metrics/v1alpha1"
	serverapiserver "github.com/apoxy-dev/apoxy/pkg/apiserver/server/apiserver"
)

// maxBodyBytes bounds the optional JSON request body. Every field of it
// mirrors a query-string parameter, so a body over this size is a probe.
const maxBodyBytes = 64 << 10

// SeriesReader runs a validated series query against the metrics backend. It
// is the only seam between the shared handler and the deployment that owns the
// ClickHouse read model.
type SeriesReader interface {
	// ReadSeries returns the series set for req. A backend that cannot be
	// reached must return Unavailable, so the client sees 503 and not 500.
	ReadSeries(ctx context.Context, req *SeriesRequest) (*metricsv1alpha1.MetricSeriesSet, error)
}

// SnapshotReader builds one owner snapshot. The returned object must be the
// kind the connecter was built for.
type SnapshotReader interface {
	// ReadSnapshot returns the snapshot for req.
	ReadSnapshot(ctx context.Context, req *SnapshotRequest) (runtime.Object, error)
}

// RecipeResolver resolves a Metric name to the compiled facts the validator
// needs. An unknown name must return NotFound.
type RecipeResolver interface {
	// Recipe returns the compiled recipe named name.
	Recipe(ctx context.Context, name string) (Recipe, error)
}

// OwnerChecker reports whether the scoped owner object exists. A read over an
// owner that does not exist is a 404 before any backend read, rather than a
// 200 full of zeros.
type OwnerChecker interface {
	// OwnerExists reports whether the object the scope names is in the store.
	OwnerExists(ctx context.Context, scope Scope) (bool, error)
}

// SeriesQuery is the optional JSON request body. Every field mirrors a query
// parameter; the query string wins when both carry the same field.
type SeriesQuery struct {
	ScopeKind     string `json:"scopeKind,omitempty"`
	ScopeName     string `json:"scopeName,omitempty"`
	ScopeListener string `json:"scopeListener,omitempty"`
	GroupBy       string `json:"groupBy,omitempty"`
	OrderBy       string `json:"orderBy,omitempty"`
	Top           int    `json:"top,omitempty"`
	Since         string `json:"since,omitempty"`
	Until         string `json:"until,omitempty"`
	Window        string `json:"window,omitempty"`
	Step          string `json:"step,omitempty"`
}

// SnapshotQuery is the optional JSON request body of a snapshot read.
type SnapshotQuery struct {
	ScopeListener string   `json:"scopeListener,omitempty"`
	Include       []string `json:"include,omitempty"`
	OrderBy       string   `json:"orderBy,omitempty"`
	Top           int      `json:"top,omitempty"`
	Since         string   `json:"since,omitempty"`
	Until         string   `json:"until,omitempty"`
	Window        string   `json:"window,omitempty"`
	Metrics       []string `json:"metric,omitempty"`
}

// SeriesOptions configures the metrics/<name>/series connecter.
type SeriesOptions struct {
	// Reader runs the query. A nil Reader makes every read a 501 that names
	// the missing configuration, so the path stays in discovery.
	Reader SeriesReader
	// Recipes resolves the recipe named by the path element.
	Recipes RecipeResolver
	// Owners is optional. When it is set, a scoped read over a missing owner
	// is a 404 before the backend is touched.
	Owners OwnerChecker
	// Cache is optional. When it is set, responses are cached under a
	// step-aligned key and the response advertises its max-age.
	Cache *Cache
	// GroupResource names the resource in a NotFound status.
	GroupResource schema.GroupResource
	// MissingFlags are named in the 501 a build with no backend returns.
	MissingFlags []string
	// Now anchors the default window. It defaults to time.Now.
	Now func() time.Time
	// Log receives the unsanitized failure next to the request id. It
	// defaults to the process default logger.
	Log *slog.Logger
}

// SnapshotOptions configures one <owner>/<name>/metrics connecter.
type SnapshotOptions struct {
	// Kind selects the response kind and the legal include tokens.
	Kind SnapshotKind
	// Source is the table the snapshot reads, which sets the window cap and
	// the cache alignment.
	Source Source
	// Reader builds the snapshot. A nil Reader makes every read a 501.
	Reader SnapshotReader
	// Decorate is optional. When it is set, it runs on a freshly read snapshot
	// before the snapshot is cached, so a decoration that comes from outside
	// the read model — such as the replica gauges off the owner status — is
	// carried by the cached object too and is not recomputed per cache hit. An
	// error from it fails the read through the same mapper as a backend error.
	Decorate func(ctx context.Context, req *SnapshotRequest, obj runtime.Object) error
	// Owners is optional. When it is set, a read over a missing owner is a 404
	// before the backend is touched.
	Owners OwnerChecker
	// Cache is optional.
	Cache *Cache
	// GroupResource names the resource in a NotFound status.
	GroupResource schema.GroupResource
	// MissingFlags are named in the 501 a build with no backend returns.
	MissingFlags []string
	// Now anchors the default window. It defaults to time.Now.
	Now func() time.Time
	// Log receives the unsanitized failure next to the request id.
	Log *slog.Logger
}

// SeriesConnecter serves metrics/<name>/series. The path element is the recipe
// name; the scope is a parameter, which is how a chart is built.
type SeriesConnecter struct {
	opts SeriesOptions
}

var (
	_ registryrest.Storage              = (*SeriesConnecter)(nil)
	_ registryrest.Scoper               = (*SeriesConnecter)(nil)
	_ registryrest.Connecter            = (*SeriesConnecter)(nil)
	_ registryrest.SingularNameProvider = (*SeriesConnecter)(nil)
)

// NewSeriesConnecter returns the series connect storage.
func NewSeriesConnecter(opts SeriesOptions) *SeriesConnecter {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.GroupResource.Empty() {
		opts.GroupResource = metricsv1alpha1.Resource("metrics")
	}
	return &SeriesConnecter{opts: opts}
}

// NewSeriesProvider adapts the series connecter to the apiserver builder.
func NewSeriesProvider(opts SeriesOptions) serverapiserver.StorageProvider {
	return func(*runtime.Scheme, generic.RESTOptionsGetter) (registryrest.Storage, error) {
		return NewSeriesConnecter(opts), nil
	}
}

// New returns the response kind, so the apiserver encodes the body to the
// right group version under content negotiation.
func (c *SeriesConnecter) New() runtime.Object { return &metricsv1alpha1.MetricSeriesSet{} }

func (c *SeriesConnecter) Destroy() {}

func (c *SeriesConnecter) NamespaceScoped() bool { return false }

func (c *SeriesConnecter) GetSingularName() string { return "series" }

func (c *SeriesConnecter) ConnectMethods() []string {
	return []string{http.MethodGet, http.MethodPost}
}

// NewConnectOptions returns no typed options. The builder installs connect
// handlers with the metav1-only ParameterCodec, so a registered options object
// cannot decode; the handler reads the query string itself.
func (c *SeriesConnecter) NewConnectOptions() (runtime.Object, bool, string) {
	return nil, false, ""
}

// Connect captures the recipe name from the path and returns the handler. The
// query string is parsed in ServeHTTP, where the request is available.
func (c *SeriesConnecter) Connect(_ context.Context, name string, _ runtime.Object, responder registryrest.Responder) (http.Handler, error) {
	if name == "" {
		return nil, apierrors.NewBadRequest("the metric name is required in the request path")
	}
	return &seriesHandler{opts: c.opts, metric: name, responder: responder}, nil
}

type seriesHandler struct {
	opts      SeriesOptions
	metric    string
	responder registryrest.Responder
}

func (h *seriesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	obj, err := h.serve(w, r)
	if err != nil {
		fail(h.opts.Log, h.responder, r, "series", err)
		return
	}
	h.responder.Object(http.StatusOK, obj)
}

func (h *seriesHandler) serve(w http.ResponseWriter, r *http.Request) (runtime.Object, error) {
	if h.opts.Reader == nil {
		return nil, NotImplemented(h.opts.MissingFlags...)
	}
	if h.opts.Recipes == nil {
		return nil, NotImplemented(h.opts.MissingFlags...)
	}

	q, err := mergeSeriesBody(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	rec, err := h.opts.Recipes.Recipe(ctx, h.metric)
	if err != nil {
		return nil, err
	}

	req, err := ParseSeriesRequest(q, rec, h.opts.Now())
	if err != nil {
		return nil, err
	}

	// A series over an owner that does not exist is a 404, not a 200 full of
	// zeros: the caller cannot tell a typo from a quiet object otherwise.
	if err := checkOwner(ctx, h.opts.Owners, req.Scope, h.opts.GroupResource); err != nil {
		return nil, err
	}

	key := SeriesCacheKey(req)
	setCacheControl(w, h.opts.Cache)
	if cached, ok := h.opts.Cache.Get(key); ok {
		return cached, nil
	}

	set, err := h.opts.Reader.ReadSeries(ctx, req)
	if err != nil {
		return nil, err
	}
	h.opts.Cache.Put(key, set)
	return set, nil
}

// SnapshotConnecter serves one <owner>/<name>/metrics path. One type serves
// every owner kind; Kind selects the response kind and the include tokens.
type SnapshotConnecter struct {
	opts SnapshotOptions
}

var (
	_ registryrest.Storage                  = (*SnapshotConnecter)(nil)
	_ registryrest.Scoper                   = (*SnapshotConnecter)(nil)
	_ registryrest.Connecter                = (*SnapshotConnecter)(nil)
	_ registryrest.SingularNameProvider     = (*SnapshotConnecter)(nil)
	_ registryrest.GroupVersionKindProvider = (*SnapshotConnecter)(nil)
)

// NewSnapshotConnecter returns the snapshot connect storage for one owner kind.
func NewSnapshotConnecter(opts SnapshotOptions) *SnapshotConnecter {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Source.Name == "" {
		opts.Source = SourceHTTP1m
	}
	return &SnapshotConnecter{opts: opts}
}

// NewSnapshotProvider adapts a snapshot connecter to the apiserver builder.
func NewSnapshotProvider(opts SnapshotOptions) serverapiserver.StorageProvider {
	return func(*runtime.Scheme, generic.RESTOptionsGetter) (registryrest.Storage, error) {
		return NewSnapshotConnecter(opts), nil
	}
}

// NewSnapshotObject returns an empty object of the given snapshot kind.
func NewSnapshotObject(kind SnapshotKind) runtime.Object {
	switch kind {
	case SnapshotGateway:
		return &metricsv1alpha1.GatewayMetrics{}
	case SnapshotHTTPRoute:
		return &metricsv1alpha1.HTTPRouteMetrics{}
	case SnapshotProxy:
		return &metricsv1alpha1.ProxyMetrics{}
	case SnapshotService:
		return &metricsv1alpha1.ServiceMetrics{}
	case SnapshotVPCNetwork:
		return &metricsv1alpha1.VPCNetworkMetrics{}
	case SnapshotTunnel:
		return &metricsv1alpha1.TunnelMetrics{}
	default:
		return nil
	}
}

func (c *SnapshotConnecter) New() runtime.Object { return NewSnapshotObject(c.opts.Kind) }

// GroupVersionKind states the kind the connecter answers with. A snapshot
// mounts on its owner kind, which lives in another group, so the apiserver
// cannot read the response kind off the mount point: without this the mount
// fails to install, and with it the response encodes in the metrics group.
func (c *SnapshotConnecter) GroupVersionKind(schema.GroupVersion) schema.GroupVersionKind {
	return metricsv1alpha1.SchemeGroupVersion.WithKind(string(c.opts.Kind))
}

func (c *SnapshotConnecter) Destroy() {}

func (c *SnapshotConnecter) NamespaceScoped() bool { return false }

func (c *SnapshotConnecter) GetSingularName() string { return "metrics" }

func (c *SnapshotConnecter) ConnectMethods() []string {
	return []string{http.MethodGet, http.MethodPost}
}

// NewConnectOptions returns no typed options; see SeriesConnecter.
func (c *SnapshotConnecter) NewConnectOptions() (runtime.Object, bool, string) {
	return nil, false, ""
}

// Connect captures the owner name from the path and returns the handler.
func (c *SnapshotConnecter) Connect(_ context.Context, name string, _ runtime.Object, responder registryrest.Responder) (http.Handler, error) {
	if name == "" {
		return nil, apierrors.NewBadRequest("the owner name is required in the request path")
	}
	return &snapshotHandler{opts: c.opts, name: name, responder: responder}, nil
}

type snapshotHandler struct {
	opts      SnapshotOptions
	name      string
	responder registryrest.Responder
}

func (h *snapshotHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	obj, err := h.serve(w, r)
	if err != nil {
		fail(h.opts.Log, h.responder, r, "snapshot", err)
		return
	}
	h.responder.Object(http.StatusOK, obj)
}

func (h *snapshotHandler) serve(w http.ResponseWriter, r *http.Request) (runtime.Object, error) {
	if h.opts.Reader == nil {
		return nil, NotImplemented(h.opts.MissingFlags...)
	}

	q, err := mergeSnapshotBody(r)
	if err != nil {
		return nil, err
	}

	req, err := ParseSnapshotRequest(q, h.opts.Kind, h.name, h.opts.Source, h.opts.Now())
	if err != nil {
		return nil, err
	}

	ctx := r.Context()
	if err := checkOwner(ctx, h.opts.Owners, req.Scope, h.opts.GroupResource); err != nil {
		return nil, err
	}

	key := SnapshotCacheKey(req)
	setCacheControl(w, h.opts.Cache)
	if cached, ok := h.opts.Cache.Get(key); ok {
		return cached, nil
	}

	snap, err := h.opts.Reader.ReadSnapshot(ctx, req)
	if err != nil {
		return nil, err
	}
	// Decorate before the object is cached, so a cache hit carries the same
	// decoration as the read that filled it.
	if h.opts.Decorate != nil {
		if err := h.opts.Decorate(ctx, req, snap); err != nil {
			return nil, err
		}
	}
	h.opts.Cache.Put(key, snap)
	return snap, nil
}

// checkOwner turns a missing owner into a 404 before any backend read.
func checkOwner(ctx context.Context, owners OwnerChecker, scope Scope, gr schema.GroupResource) error {
	if owners == nil || scope.Kind == ScopeProject || scope.Name == "" {
		return nil
	}
	ok, err := owners.OwnerExists(ctx, scope)
	if err != nil {
		return err
	}
	if !ok {
		return NotFound(gr, scope.Name)
	}
	return nil
}

// setCacheControl advertises the cache TTL, so a console polls on the interval
// the response states instead of guessing one.
func setCacheControl(w http.ResponseWriter, c *Cache) {
	if w == nil || c == nil || c.TTL() <= 0 {
		return
	}
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(c.TTL()/time.Second)))
}

// fail logs the unsanitized failure next to the request id and answers with
// the mapped status. The client message carries the same id, so a report can
// be traced back to the log record without the error carrying any SQL.
// A client error (4xx) is a rejected request, not a fault in the server, so
// it is logged at Info; only a 5xx is an Error.
func fail(log *slog.Logger, responder registryrest.Responder, r *http.Request, verb string, err error) {
	id := r.Header.Get("Audit-ID")
	code := StatusCode(err)
	level := slog.LevelError
	if code < http.StatusInternalServerError {
		level = slog.LevelInfo
	}
	log.Log(r.Context(), level, "Metrics read failed",
		"verb", verb,
		"path", r.URL.Path,
		"requestID", id,
		"status", code,
		"error", err)

	status := ToStatusError(verb, err)
	var statusErr *apierrors.StatusError
	if id != "" && errors.As(status, &statusErr) {
		statusErr.ErrStatus.Message = fmt.Sprintf("%s (request %s)", statusErr.ErrStatus.Message, id)
		status = statusErr
	}
	responder.Error(status)
}

// mergeSeriesBody merges the optional JSON body under the query string, which
// wins on a conflict.
func mergeSeriesBody(r *http.Request) (url.Values, error) {
	q := cloneValues(r.URL.Query())
	var body SeriesQuery
	ok, err := decodeBody(r, &body)
	if err != nil || !ok {
		return q, err
	}
	setDefault(q, "scopeKind", body.ScopeKind)
	setDefault(q, "scopeName", body.ScopeName)
	setDefault(q, "scopeListener", body.ScopeListener)
	setDefault(q, "groupBy", body.GroupBy)
	setDefault(q, "orderBy", body.OrderBy)
	setDefault(q, "since", body.Since)
	setDefault(q, "until", body.Until)
	setDefault(q, "window", body.Window)
	setDefault(q, "step", body.Step)
	if body.Top > 0 {
		setDefault(q, "top", strconv.Itoa(body.Top))
	}
	return q, nil
}

// mergeSnapshotBody merges the optional JSON body under the query string.
func mergeSnapshotBody(r *http.Request) (url.Values, error) {
	q := cloneValues(r.URL.Query())
	var body SnapshotQuery
	ok, err := decodeBody(r, &body)
	if err != nil || !ok {
		return q, err
	}
	setDefault(q, "scopeListener", body.ScopeListener)
	setDefault(q, "orderBy", body.OrderBy)
	setDefault(q, "since", body.Since)
	setDefault(q, "until", body.Until)
	setDefault(q, "window", body.Window)
	if body.Top > 0 {
		setDefault(q, "top", strconv.Itoa(body.Top))
	}
	if len(q["include"]) == 0 {
		q["include"] = append([]string(nil), body.Include...)
	}
	if len(q["metric"]) == 0 {
		q["metric"] = append([]string(nil), body.Metrics...)
	}
	return q, nil
}

// decodeBody reads the optional JSON body. The false return means there was
// none, which is the usual case for a GET.
func decodeBody(r *http.Request, into any) (bool, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return false, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return false, BadRequest("cannot read the request body")
	}
	if len(raw) == 0 {
		return false, nil
	}
	if len(raw) > maxBodyBytes {
		return false, BadRequest("the request body is larger than %d bytes", maxBodyBytes)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return false, BadRequest("the request body is not valid JSON")
	}
	return true, nil
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func setDefault(q url.Values, key, val string) {
	if val == "" || q.Get(key) != "" {
		return
	}
	q.Set(key, val)
}
