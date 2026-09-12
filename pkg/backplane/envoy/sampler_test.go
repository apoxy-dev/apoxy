package envoy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminServer serves the Envoy admin paths the sampler reads.
func adminServer(t *testing.T, stats, serverInfo, configDump string) *Runtime {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasPrefix(req.URL.Path, "/stats"):
			if stats == "" {
				http.Error(w, "no stats", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(stats))
		case req.URL.Path == "/server_info":
			w.Write([]byte(serverInfo))
		case req.URL.Path == "/config_dump":
			w.Write([]byte(configDump))
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)

	return &Runtime{adminHost: strings.TrimPrefix(srv.URL, "http://")}
}

func TestReadAdminStats(t *testing.T) {
	cases := []struct {
		name         string
		stats        string
		wantErr      bool
		wantTotal    int64
		wantRequests int64
		wantConns    int64
	}{
		{
			name: "one listener",
			stats: `{"stats":[
				{"name":"server.total_connections","value":42},
				{"name":"http.http-80.downstream_rq_active","value":7},
				{"name":"http.http-80.downstream_cx_active","value":11}
			]}`,
			wantTotal: 42, wantRequests: 7, wantConns: 11,
		},
		{
			name: "two listeners are summed",
			stats: `{"stats":[
				{"name":"server.total_connections","value":42},
				{"name":"http.http-80.downstream_rq_active","value":7},
				{"name":"http.http-443.downstream_rq_active","value":3},
				{"name":"http.http-80.downstream_cx_active","value":11},
				{"name":"http.http-443.downstream_cx_active","value":5}
			]}`,
			wantTotal: 42, wantRequests: 10, wantConns: 16,
		},
		{
			name:  "no stats match",
			stats: `{"stats":[]}`,
		},
		{
			name:    "admin interface is down",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := adminServer(t, tc.stats, "", "")

			got, err := r.readAdminStats(context.Background(), http.DefaultClient)

			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantTotal, got.TotalConnections)
			assert.Equal(t, tc.wantRequests, got.RequestsInFlight)
			assert.Equal(t, tc.wantConns, got.Connections)
			assert.WithinDuration(t, time.Now(), got.At, time.Minute)
		})
	}
}

func TestSampleOnceCountsScrapeErrors(t *testing.T) {
	r := adminServer(t, "", "", "")

	r.sampleOnce(context.Background(), http.DefaultClient)

	assert.Equal(t, int64(1), r.tel.adminScrapeErrors.Load())
	assert.Nil(t, r.tel.lastSample)
}

func TestSampleOnceReadsTheEnvoyVersion(t *testing.T) {
	r := adminServer(t,
		`{"stats":[{"name":"server.total_connections","value":1}]}`,
		`{"version":"a1b2c3/1.35.13/Clean/RELEASE/BoringSSL","state":"LIVE"}`,
		"")

	r.sampleOnce(context.Background(), http.DefaultClient)

	require.NotNil(t, r.tel.lastSample)
	assert.Equal(t, int64(1), r.tel.lastSample.TotalConnections)
	assert.Equal(t, "1.35.13", r.tel.envoyVersion)
	assert.Zero(t, r.tel.adminScrapeErrors.Load())
}

func TestEnvoyVersionFromServerInfo(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "full build string", input: "a1b2c3/1.35.13/Clean/RELEASE/BoringSSL", want: "1.35.13"},
		{name: "plain version", input: "1.35.13", want: "1.35.13"},
		{name: "empty version", input: "", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, envoyVersionFromServerInfo(tc.input))
		})
	}
}

func TestCollectDNSCacheLimits(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  map[string]uint64
	}{
		{
			name: "cluster config dump",
			input: `{"configs":[{"dynamic_active_clusters":[{"cluster":{"name":"dfp",
				"cluster_type":{"typed_config":{"dns_cache_config":{"name":"dynamic-proxy","max_hosts":2048}}}}}]}]}`,
			want: map[string]uint64{"dynamic_proxy": 2048},
		},
		{
			name:  "limit is a string",
			input: `{"dns_cache_config":{"name":"cache.one","max_hosts":"1024"}}`,
			want:  map[string]uint64{"cache_one": 1024},
		},
		{
			name:  "limit is left out",
			input: `{"dns_cache_config":{"name":"dynamic-proxy"}}`,
			want:  map[string]uint64{},
		},
		{
			name:  "no cache is configured",
			input: `{"configs":[]}`,
			want:  map[string]uint64{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dump any
			require.NoError(t, json.Unmarshal([]byte(tc.input), &dump))

			got := make(map[string]uint64)
			collectDNSCacheLimits(dump, got)

			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSanitizeStatName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "hyphen becomes an underscore", input: "dynamic-proxy", want: "dynamic_proxy"},
		{name: "dot becomes an underscore", input: "cache.one", want: "cache_one"},
		{name: "name is already safe", input: "dynamic_proxy0", want: "dynamic_proxy0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeStatName(tc.input))
		})
	}
}

func TestSampleOnceKeepsTheTCPCounters(t *testing.T) {
	cases := []struct {
		name     string
		stats    string
		readers  bool
		wantTCP  bool
		wantStat bool
	}{
		{
			name:     "admin and kernel answer",
			stats:    `{"stats":[{"name":"server.total_connections","value":1}]}`,
			readers:  true,
			wantTCP:  true,
			wantStat: true,
		},
		{
			name:    "admin is down, kernel answers",
			readers: true,
			wantTCP: true,
		},
		{
			name:     "kernel counters are not readable",
			stats:    `{"stats":[{"name":"server.total_connections","value":1}]}`,
			wantStat: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.readers {
				useStubReaders(t, &stubReaders{tcp: tcpCounters{EstabResets: 9}})
			} else {
				useStubReaders(t, nil)
			}
			r := adminServer(t, tc.stats, "", "")

			r.sampleOnce(context.Background(), http.DefaultClient)

			if tc.wantTCP {
				require.NotNil(t, r.tel.lastTCP)
				assert.Equal(t, int64(9), r.tel.lastTCP.EstabResets)
			} else {
				assert.Nil(t, r.tel.lastTCP)
			}
			if tc.wantStat {
				assert.NotNil(t, r.tel.lastSample)
			} else {
				assert.Nil(t, r.tel.lastSample)
			}
		})
	}
}

func TestStartSamplerWaitsForTheSamplerToStop(t *testing.T) {
	inRequest := make(chan struct{}, 1)
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case inRequest <- struct{}{}:
		default:
		}
		// Hold the answer back so that the stop happens while a read is in
		// flight.
		select {
		case <-blocked:
		case <-req.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(blocked)

	r := &Runtime{adminHost: strings.TrimPrefix(srv.URL, "http://")}
	stop := r.startSampler(context.Background())

	select {
	case <-inRequest:
	case <-time.After(5 * time.Second):
		t.Fatal("the sampler did not read the admin interface")
	}

	stop()

	// The read was cancelled, and its bookkeeping is finished when stop
	// returns. A stop that does not wait leaves this at zero.
	assert.Equal(t, int64(1), r.tel.adminScrapeErrors.Load())
	assert.Nil(t, r.tel.lastSample)
}

func TestSampleLoopSchedulesTheDNSCacheReads(t *testing.T) {
	const dumpWithCache = `{"configs":[{"dynamic_active_clusters":[{"cluster":{"name":"dfp",
		"cluster_type":{"typed_config":{"dns_cache_config":{"name":"dynamic-proxy","max_hosts":1024}}}}}]}]}`

	cases := []struct {
		name string
		// emptyDumps is how many reads answer before the cluster arrives over
		// xDS. A negative value never answers with a cache.
		emptyDumps int
		settleTime time.Duration
		// minWait is how long the reads need to settle.
		minWait      time.Duration
		wantMinReads int
		wantLimits   map[string]uint64
	}{
		{
			name:         "the cache arrives after the cluster",
			emptyDumps:   3,
			settleTime:   time.Minute,
			minWait:      0,
			wantMinReads: 4,
			wantLimits:   map[string]uint64{"dynamic_proxy": 1024},
		},
		{
			name:         "no cache is configured",
			emptyDumps:   -1,
			settleTime:   50 * time.Millisecond,
			minWait:      150 * time.Millisecond,
			wantMinReads: 5,
			wantLimits:   map[string]uint64{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			dumps := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if !strings.HasPrefix(req.URL.Path, "/config_dump") {
					w.Write([]byte(`{"stats":[]}`))
					return
				}
				mu.Lock()
				dumps++
				serveCache := tc.emptyDumps >= 0 && dumps > tc.emptyDumps
				mu.Unlock()
				if serveCache {
					w.Write([]byte(dumpWithCache))
					return
				}
				w.Write([]byte(`{"configs":[]}`))
			}))
			defer srv.Close()

			readDumps := func() int {
				mu.Lock()
				defer mu.Unlock()
				return dumps
			}

			r := &Runtime{adminHost: strings.TrimPrefix(srv.URL, "http://")}
			r.tel.intervals = samplerIntervals{
				Sample:     time.Hour,
				CacheRetry: 5 * time.Millisecond,
				// A long refresh makes the settled schedule visible: the reads
				// must stop once the limits settled.
				CacheSettleTime: tc.settleTime,
				CacheRefresh:    time.Hour,
			}

			startedAt := time.Now()
			stop := r.startSampler(context.Background())
			defer stop()

			// The retries run until a cache shows up or the settle time ends.
			require.Eventually(t, func() bool {
				if time.Since(startedAt) < tc.minWait || readDumps() < tc.wantMinReads {
					return false
				}
				r.tel.mu.RLock()
				defer r.tel.mu.RUnlock()
				return len(r.tel.dnsCacheMaxHosts) == len(tc.wantLimits)
			}, 5*time.Second, 5*time.Millisecond)

			settledAt := readDumps()
			require.Never(t, func() bool {
				return readDumps() > settledAt
			}, 150*time.Millisecond, 10*time.Millisecond)

			r.tel.mu.RLock()
			defer r.tel.mu.RUnlock()
			assert.Equal(t, tc.wantLimits, r.tel.dnsCacheMaxHosts)
		})
	}
}

func TestSampleLoopStopsWithTheProcess(t *testing.T) {
	r := adminServer(t, `{"stats":[{"name":"server.total_connections","value":3}]}`, `{"version":"1.35.13"}`, "{}")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.sampleLoop(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool {
		r.tel.mu.RLock()
		defer r.tel.mu.RUnlock()
		return r.tel.lastSample != nil
	}, 5*time.Second, 10*time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sampler did not stop")
	}

	r.tel.mu.RLock()
	defer r.tel.mu.RUnlock()
	assert.Equal(t, int64(3), r.tel.lastSample.TotalConnections)
}
