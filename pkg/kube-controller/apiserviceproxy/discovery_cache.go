package apiserviceproxy

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	defaultDiscoveryCacheTTL       = time.Minute
	maxDiscoveryCacheResponseBytes = 2 << 20
	maxDiscoveryCacheBytes         = 16 << 20
	maxDiscoveryCacheEntries       = 128
)

// discoveryCacheTransport caches the small, stable discovery responses used by
// kube-aggregator. The cache lives in each customer-side kube-controller pod,
// which keeps repeated health and OpenAPI checks from crossing the customer
// VPC boundary.
type discoveryCacheTransport struct {
	next http.RoundTripper
	ttl  time.Duration
	now  func() time.Time

	mu          sync.Mutex
	entries     map[string]discoveryCacheEntry
	cachedBytes int
	flights     singleflight.Group
}

type discoveryCacheEntry struct {
	response  *cachedDiscoveryResponse
	expiresAt time.Time
}

type discoveryFlightResult struct {
	response    *cachedDiscoveryResponse
	passthrough *http.Response
	cacheable   bool
}

type cachedDiscoveryResponse struct {
	status           string
	statusCode       int
	proto            string
	protoMajor       int
	protoMinor       int
	header           http.Header
	body             []byte
	contentLength    int64
	transferEncoding []string
	close            bool
	uncompressed     bool
	trailer          http.Header
}

func newDiscoveryCacheTransport(next http.RoundTripper, ttl time.Duration) *discoveryCacheTransport {
	if next == nil {
		next = http.DefaultTransport
	}
	return &discoveryCacheTransport{
		next:    next,
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[string]discoveryCacheEntry),
	}
}

func (t *discoveryCacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.ttl <= 0 || !isCacheableDiscoveryRequest(req) {
		return t.next.RoundTrip(req)
	}

	key := discoveryCacheKey(req)
	if response, ok := t.load(key); ok {
		return response.toHTTPResponse(req), nil
	}

	// DoChan lets the caller whose function actually runs distinguish itself
	// from waiters. If the upstream response fails, only successful responses
	// are shared: waiters retry independently, preserving kube-aggregator's
	// multiple-attempt availability semantics.
	executed := false
	resultCh := t.flights.DoChan(key, func() (any, error) {
		executed = true
		if response, ok := t.load(key); ok {
			return discoveryFlightResult{response: response, cacheable: true}, nil
		}

		response, err := t.next.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		cached, passthrough, err := captureDiscoveryResponse(response)
		if err != nil {
			return nil, err
		}
		if passthrough != nil {
			return discoveryFlightResult{passthrough: passthrough}, nil
		}

		cacheable := isCacheableDiscoveryStatus(cached.statusCode)
		if cacheable {
			t.store(key, cached)
		}
		return discoveryFlightResult{response: cached, cacheable: cacheable}, nil
	})

	var result singleflight.Result
	select {
	case result = <-resultCh:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	if result.Err != nil {
		if executed {
			return nil, result.Err
		}
		return t.next.RoundTrip(req)
	}

	flightResult := result.Val.(discoveryFlightResult)
	if flightResult.passthrough != nil {
		if executed {
			return flightResult.passthrough, nil
		}
		return t.next.RoundTrip(req)
	}
	if flightResult.cacheable || executed {
		return flightResult.response.toHTTPResponse(req), nil
	}

	// Do not share or retain an unsuccessful response. Every waiting
	// availability probe gets its own upstream attempt.
	return t.next.RoundTrip(req)
}

func (t *discoveryCacheTransport) load(key string) (*cachedDiscoveryResponse, bool) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.expiresAt) {
		t.cachedBytes -= len(entry.response.body)
		delete(t.entries, key)
		return nil, false
	}
	return entry.response, true
}

func (t *discoveryCacheTransport) store(key string, response *cachedDiscoveryResponse) {
	if len(response.body) > maxDiscoveryCacheBytes {
		return
	}

	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	for existingKey, entry := range t.entries {
		if !now.Before(entry.expiresAt) {
			t.cachedBytes -= len(entry.response.body)
			delete(t.entries, existingKey)
		}
	}
	if previous, ok := t.entries[key]; ok {
		t.cachedBytes -= len(previous.response.body)
		delete(t.entries, key)
	}
	for len(t.entries) >= maxDiscoveryCacheEntries || t.cachedBytes+len(response.body) > maxDiscoveryCacheBytes {
		var oldestKey string
		var oldestExpiry time.Time
		for existingKey, entry := range t.entries {
			if oldestKey == "" || entry.expiresAt.Before(oldestExpiry) {
				oldestKey = existingKey
				oldestExpiry = entry.expiresAt
			}
		}
		t.cachedBytes -= len(t.entries[oldestKey].response.body)
		delete(t.entries, oldestKey)
	}

	t.entries[key] = discoveryCacheEntry{
		response:  response,
		expiresAt: now.Add(t.ttl),
	}
	t.cachedBytes += len(response.body)
}

func isCacheableDiscoveryRequest(req *http.Request) bool {
	if req.Method != http.MethodGet {
		return false
	}
	if !isKubeAggregatorUser(req.Header.Get("X-Remote-User")) {
		return false
	}
	if len(req.Header.Values("Range")) > 0 || len(req.Header.Values("If-Range")) > 0 {
		return false
	}
	cacheControl := strings.ToLower(req.Header.Get("Cache-Control"))
	if strings.Contains(cacheControl, "no-cache") || strings.Contains(cacheControl, "no-store") {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(req.Header.Get("Pragma")), "no-cache") {
		return false
	}

	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	switch {
	case req.URL.Path == "/apis", req.URL.Path == "/api", req.URL.Path == "/openapi/v2":
		return true
	case len(parts) == 3 && parts[0] == "apis" && parts[1] != "" && parts[2] != "":
		return true
	case len(parts) == 2 && parts[0] == "api" && parts[1] != "":
		return true
	default:
		return false
	}
}

func isKubeAggregatorUser(user string) bool {
	return user == "system:kube-aggregator" || user == "system:aggregator"
}

func isCacheableDiscoveryStatus(status int) bool {
	return status == http.StatusOK || status == http.StatusNotModified
}

func discoveryCacheKey(req *http.Request) string {
	var key strings.Builder
	key.WriteString(req.Method)
	key.WriteByte('\n')
	key.WriteString(req.URL.EscapedPath())
	key.WriteByte('?')
	key.WriteString(req.URL.RawQuery)

	for _, name := range []string{
		"Accept",
		"Accept-Encoding",
		"Authorization",
		"If-Modified-Since",
		"If-None-Match",
		"X-Remote-Uid",
		"X-Remote-User",
	} {
		key.WriteByte('\n')
		key.WriteString(name)
		key.WriteByte(':')
		key.WriteString(req.Header.Get(name))
	}

	groups := append([]string(nil), req.Header.Values("X-Remote-Group")...)
	sort.Strings(groups)
	for _, group := range groups {
		key.WriteString("\nX-Remote-Group:")
		key.WriteString(group)
	}

	extraNames := make([]string, 0)
	for name := range req.Header {
		canonicalName := http.CanonicalHeaderKey(name)
		if strings.HasPrefix(canonicalName, "X-Remote-Extra-") {
			extraNames = append(extraNames, canonicalName)
		}
	}
	sort.Strings(extraNames)
	for _, name := range extraNames {
		values := append([]string(nil), req.Header.Values(name)...)
		sort.Strings(values)
		for _, value := range values {
			key.WriteByte('\n')
			key.WriteString(name)
			key.WriteByte(':')
			key.WriteString(value)
		}
	}

	digest := sha256.Sum256([]byte(key.String()))
	return string(digest[:])
}

func captureDiscoveryResponse(response *http.Response) (*cachedDiscoveryResponse, *http.Response, error) {
	if response.Body == nil {
		response.Body = http.NoBody
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryCacheResponseBytes+1))
	if err != nil {
		response.Body.Close()
		return nil, nil, err
	}
	if len(body) > maxDiscoveryCacheResponseBytes {
		originalBody := response.Body
		response.Body = &prefixedReadCloser{
			Reader: io.MultiReader(bytes.NewReader(body), originalBody),
			Closer: originalBody,
		}
		return nil, response, nil
	}
	response.Body.Close()

	return &cachedDiscoveryResponse{
		status:           response.Status,
		statusCode:       response.StatusCode,
		proto:            response.Proto,
		protoMajor:       response.ProtoMajor,
		protoMinor:       response.ProtoMinor,
		header:           response.Header.Clone(),
		body:             append([]byte(nil), body...),
		contentLength:    response.ContentLength,
		transferEncoding: append([]string(nil), response.TransferEncoding...),
		close:            response.Close,
		uncompressed:     response.Uncompressed,
		trailer:          response.Trailer.Clone(),
	}, nil, nil
}

func (r *cachedDiscoveryResponse) toHTTPResponse(req *http.Request) *http.Response {
	return &http.Response{
		Status:           r.status,
		StatusCode:       r.statusCode,
		Proto:            r.proto,
		ProtoMajor:       r.protoMajor,
		ProtoMinor:       r.protoMinor,
		Header:           r.header.Clone(),
		Body:             io.NopCloser(bytes.NewReader(r.body)),
		ContentLength:    r.contentLength,
		TransferEncoding: append([]string(nil), r.transferEncoding...),
		Close:            r.close,
		Uncompressed:     r.uncompressed,
		Trailer:          r.trailer.Clone(),
		Request:          req,
	}
}

type prefixedReadCloser struct {
	io.Reader
	io.Closer
}
