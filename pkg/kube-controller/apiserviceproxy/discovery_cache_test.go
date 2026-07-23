package apiserviceproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIsCacheableDiscoveryRequest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		method       string
		path         string
		user         string
		cacheControl string
		rangeHeader  string
		ifRange      string
		want         bool
	}{
		{name: "API groups", method: http.MethodGet, path: "/apis", user: "system:kube-aggregator", want: true},
		{name: "API group version", method: http.MethodGet, path: "/apis/gateway.apoxy.dev/v1", user: "system:kube-aggregator", want: true},
		{name: "legacy API root", method: http.MethodGet, path: "/api", user: "system:kube-aggregator", want: true},
		{name: "legacy API version", method: http.MethodGet, path: "/api/v1", user: "system:kube-aggregator", want: true},
		{name: "OpenAPI v2", method: http.MethodGet, path: "/openapi/v2", user: "system:aggregator", want: true},
		{name: "resource collection", method: http.MethodGet, path: "/apis/gateway.apoxy.dev/v1/gateways", user: "system:kube-aggregator", want: false},
		{name: "unrecognized OpenAPI path", method: http.MethodGet, path: "/openapi/v3", user: "system:aggregator", want: false},
		{name: "non-aggregator user", method: http.MethodGet, path: "/apis/gateway.apoxy.dev/v1", user: "alice", want: false},
		{name: "non-GET request", method: http.MethodPost, path: "/apis/gateway.apoxy.dev/v1", user: "system:kube-aggregator", want: false},
		{name: "explicit bypass", method: http.MethodGet, path: "/apis/gateway.apoxy.dev/v1", user: "system:kube-aggregator", cacheControl: "no-cache", want: false},
		{name: "range request", method: http.MethodGet, path: "/openapi/v2", user: "system:aggregator", rangeHeader: "bytes=0-99", want: false},
		{name: "conditional range request", method: http.MethodGet, path: "/openapi/v2", user: "system:aggregator", ifRange: `"openapi-etag"`, want: false},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := newDiscoveryCacheRequest(t, tc.method, tc.path, tc.user)
			if tc.cacheControl != "" {
				req.Header.Set("Cache-Control", tc.cacheControl)
			}
			if tc.rangeHeader != "" {
				req.Header.Set("Range", tc.rangeHeader)
			}
			if tc.ifRange != "" {
				req.Header.Set("If-Range", tc.ifRange)
			}
			require.Equal(t, tc.want, isCacheableDiscoveryRequest(req))
		})
	}
}

func TestDiscoveryCacheTransportCachesSuccessfulResponseUntilExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	transport := newDiscoveryCacheTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		call := calls.Add(1)
		body := fmt.Sprintf("response-%d", call)
		return newDiscoveryCacheResponse(http.StatusOK, body, http.Header{"Etag": []string{fmt.Sprintf("etag-%d", call)}}), nil
	}), time.Minute)
	transport.now = func() time.Time { return now }

	first := roundTripDiscovery(t, transport, newDiscoveryCacheRequest(t, http.MethodGet, "/apis/core.apoxy.dev/v1alpha", "system:kube-aggregator"))
	require.Equal(t, "response-1", readDiscoveryResponseBody(t, first))
	require.Equal(t, "etag-1", first.Header.Get("Etag"))
	first.Header.Set("Etag", "mutated")

	now = now.Add(59 * time.Second)
	second := roundTripDiscovery(t, transport, newDiscoveryCacheRequest(t, http.MethodGet, "/apis/core.apoxy.dev/v1alpha", "system:kube-aggregator"))
	require.Equal(t, "response-1", readDiscoveryResponseBody(t, second))
	require.Equal(t, "etag-1", second.Header.Get("Etag"))
	require.EqualValues(t, 1, calls.Load())

	now = now.Add(2 * time.Second)
	third := roundTripDiscovery(t, transport, newDiscoveryCacheRequest(t, http.MethodGet, "/apis/core.apoxy.dev/v1alpha", "system:kube-aggregator"))
	require.Equal(t, "response-2", readDiscoveryResponseBody(t, third))
	require.EqualValues(t, 2, calls.Load())
}

func TestDiscoveryCacheTransportVariesByRequestMetadata(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	transport := newDiscoveryCacheTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		call := calls.Add(1)
		return newDiscoveryCacheResponse(http.StatusOK, fmt.Sprintf("response-%d", call), nil), nil
	}), time.Minute)

	testCases := []struct {
		name      string
		user      string
		accept    string
		etag      string
		groups    []string
		wantCalls int32
	}{
		{name: "initial request", user: "system:kube-aggregator", accept: "application/json", etag: "one", groups: []string{"system:masters", "one"}, wantCalls: 1},
		{name: "same metadata", user: "system:kube-aggregator", accept: "application/json", etag: "one", groups: []string{"system:masters", "one"}, wantCalls: 1},
		{name: "group order is normalized", user: "system:kube-aggregator", accept: "application/json", etag: "one", groups: []string{"one", "system:masters"}, wantCalls: 1},
		{name: "different ETag", user: "system:kube-aggregator", accept: "application/json", etag: "two", groups: []string{"one", "system:masters"}, wantCalls: 2},
		{name: "different accept", user: "system:kube-aggregator", accept: "application/vnd.kubernetes.protobuf", etag: "two", groups: []string{"one", "system:masters"}, wantCalls: 3},
		{name: "different aggregator identity", user: "system:aggregator", accept: "application/vnd.kubernetes.protobuf", etag: "two", groups: []string{"one", "system:masters"}, wantCalls: 4},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := newDiscoveryCacheRequest(t, http.MethodGet, "/openapi/v2", tc.user)
			req.Header.Set("Accept", tc.accept)
			req.Header.Set("If-None-Match", tc.etag)
			for _, group := range tc.groups {
				req.Header.Add("X-Remote-Group", group)
			}
			response := roundTripDiscovery(t, transport, req)
			readDiscoveryResponseBody(t, response)
			require.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}

func TestDiscoveryCacheTransportCachesOnlyCompleteResponses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		status    int
		wantCalls int32
	}{
		{name: "OK", status: http.StatusOK, wantCalls: 1},
		{name: "no content", status: http.StatusNoContent, wantCalls: 2},
		{name: "partial content", status: http.StatusPartialContent, wantCalls: 2},
		{name: "not modified", status: http.StatusNotModified, wantCalls: 1},
		{name: "service unavailable", status: http.StatusServiceUnavailable, wantCalls: 2},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			transport := newDiscoveryCacheTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return newDiscoveryCacheResponse(tc.status, http.StatusText(tc.status), nil), nil
			}), time.Minute)

			for range 2 {
				response := roundTripDiscovery(t, transport, newDiscoveryCacheRequest(t, http.MethodGet, "/apis/core.apoxy.dev/v1alpha", "system:kube-aggregator"))
				readDiscoveryResponseBody(t, response)
			}
			require.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}

func TestDiscoveryCacheTransportStopsWaitingAfterCancellation(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	upstreamStarted := make(chan struct{})
	releaseUpstream := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
	}
	t.Cleanup(release)

	transport := newDiscoveryCacheTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		close(upstreamStarted)
		<-releaseUpstream
		return newDiscoveryCacheResponse(http.StatusOK, "discovery", nil), nil
	}), time.Minute)

	leaderDone := make(chan error, 1)
	leaderRequest := newDiscoveryCacheRequest(t, http.MethodGet, "/apis/core.apoxy.dev/v1alpha", "system:kube-aggregator")
	go func() {
		response, err := transport.RoundTrip(leaderRequest)
		if response != nil {
			_ = response.Body.Close()
		}
		leaderDone <- err
	}()

	select {
	case <-upstreamStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the leading discovery request")
	}

	waiterContext, cancelWaiter := context.WithCancel(context.Background())
	waiterRequest := newDiscoveryCacheRequest(t, http.MethodGet, "/apis/core.apoxy.dev/v1alpha", "system:kube-aggregator").WithContext(waiterContext)
	cancelWaiter()

	waiterDone := make(chan error, 1)
	go func() {
		_, err := transport.RoundTrip(waiterRequest)
		waiterDone <- err
	}()

	select {
	case err := <-waiterDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		release()
		t.Fatal("canceled waiter remained blocked on the discovery flight")
	}
	require.EqualValues(t, 1, calls.Load())

	release()
	select {
	case err := <-leaderDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the leading discovery request to finish")
	}
}

func TestDiscoveryCacheTransportDoesNotMixFullAndRangedResponses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		requests []bool
	}{
		{name: "range then full", requests: []bool{true, false, false}},
		{name: "full then range", requests: []bool{false, true, false}},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			transport := newDiscoveryCacheTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				if req.Header.Get("Range") != "" {
					return newDiscoveryCacheResponse(http.StatusPartialContent, "partial", nil), nil
				}
				return newDiscoveryCacheResponse(http.StatusOK, "full", nil), nil
			}), time.Minute)

			for _, ranged := range tc.requests {
				req := newDiscoveryCacheRequest(t, http.MethodGet, "/openapi/v2", "system:aggregator")
				wantStatus := http.StatusOK
				wantBody := "full"
				if ranged {
					req.Header.Set("Range", "bytes=0-99")
					wantStatus = http.StatusPartialContent
					wantBody = "partial"
				}

				response := roundTripDiscovery(t, transport, req)
				require.Equal(t, wantStatus, response.StatusCode)
				require.Equal(t, wantBody, readDiscoveryResponseBody(t, response))
			}
			require.EqualValues(t, 2, calls.Load())
		})
	}
}

func TestDiscoveryCacheTransportCoalescesConcurrentSuccesses(t *testing.T) {
	t.Parallel()

	const requestCount = 5
	var calls atomic.Int32
	upstreamStarted := make(chan struct{})
	releaseUpstream := make(chan struct{})
	var startOnce sync.Once
	transport := newDiscoveryCacheTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		startOnce.Do(func() { close(upstreamStarted) })
		<-releaseUpstream
		return newDiscoveryCacheResponse(http.StatusOK, "discovery", nil), nil
	}), time.Minute)

	start := make(chan struct{})
	results := make(chan string, requestCount)
	errors := make(chan error, requestCount)
	requests := make([]*http.Request, requestCount)
	for i := range requests {
		requests[i] = newDiscoveryCacheRequest(t, http.MethodGet, "/apis/core.apoxy.dev/v1alpha", "system:kube-aggregator")
	}
	var ready sync.WaitGroup
	ready.Add(requestCount)
	for _, req := range requests {
		req := req
		go func() {
			ready.Done()
			<-start
			response, err := transport.RoundTrip(req)
			if err != nil {
				errors <- err
				return
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				errors <- err
				return
			}
			results <- string(body)
		}()
	}
	ready.Wait()
	close(start)
	<-upstreamStarted

	// Give every caller time to join the in-flight request before releasing
	// the upstream response. The upstream remains blocked throughout.
	time.Sleep(25 * time.Millisecond)
	close(releaseUpstream)

	for range requestCount {
		select {
		case err := <-errors:
			require.NoError(t, err)
		case body := <-results:
			require.Equal(t, "discovery", body)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for cached discovery response")
		}
	}
	require.EqualValues(t, 1, calls.Load())
}

func TestDiscoveryCacheTransportPreservesConcurrentFailureAttempts(t *testing.T) {
	t.Parallel()

	const requestCount = 5
	var calls atomic.Int32
	firstUpstreamStarted := make(chan struct{})
	releaseFirstUpstream := make(chan struct{})
	transport := newDiscoveryCacheTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		call := calls.Add(1)
		if call == 1 {
			close(firstUpstreamStarted)
			<-releaseFirstUpstream
		}
		return newDiscoveryCacheResponse(http.StatusServiceUnavailable, "unavailable", nil), nil
	}), time.Minute)

	start := make(chan struct{})
	statuses := make(chan int, requestCount)
	errors := make(chan error, requestCount)
	requests := make([]*http.Request, requestCount)
	for i := range requests {
		requests[i] = newDiscoveryCacheRequest(t, http.MethodGet, "/apis/core.apoxy.dev/v1alpha", "system:kube-aggregator")
	}
	var ready sync.WaitGroup
	ready.Add(requestCount)
	for _, req := range requests {
		req := req
		go func() {
			ready.Done()
			<-start
			response, err := transport.RoundTrip(req)
			if err != nil {
				errors <- err
				return
			}
			response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	ready.Wait()
	close(start)
	<-firstUpstreamStarted
	time.Sleep(25 * time.Millisecond)
	close(releaseFirstUpstream)

	for range requestCount {
		select {
		case err := <-errors:
			require.NoError(t, err)
		case status := <-statuses:
			require.Equal(t, http.StatusServiceUnavailable, status)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for discovery failure response")
		}
	}
	require.EqualValues(t, requestCount, calls.Load())
}

func TestDiscoveryCacheTransportDoesNotCacheOversizedResponse(t *testing.T) {
	t.Parallel()

	body := bytes.Repeat([]byte("x"), maxDiscoveryCacheResponseBytes+1)
	var calls atomic.Int32
	transport := newDiscoveryCacheTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return newDiscoveryCacheResponse(http.StatusOK, string(body), nil), nil
	}), time.Minute)

	for range 2 {
		response := roundTripDiscovery(t, transport, newDiscoveryCacheRequest(t, http.MethodGet, "/openapi/v2", "system:aggregator"))
		got, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, body, got)
	}
	require.EqualValues(t, 2, calls.Load())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newDiscoveryCacheRequest(t *testing.T, method, path, user string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://project.apiz.apoxy.dev"+path, nil)
	require.NoError(t, err)
	req.Header.Set("X-Remote-User", user)
	return req
}

func newDiscoveryCacheResponse(status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
	}
}

func roundTripDiscovery(t *testing.T, transport http.RoundTripper, req *http.Request) *http.Response {
	t.Helper()
	response, err := transport.RoundTrip(req)
	require.NoError(t, err)
	return response
}

func readDiscoveryResponseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	return string(body)
}
