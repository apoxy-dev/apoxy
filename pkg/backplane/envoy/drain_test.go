package envoy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/bootstrap"
)

// The fixtures in testdata/drain are real Envoy v1.35.13 admin responses
// (--concurrency 4, an HTTP listener and a tls_inspector + tcp_proxy
// listener, one idle admin connection open). See testdata/drain/README.md.

type drainFixture struct {
	stats []byte
	dump  []byte
}

func loadDrainFixture(t *testing.T, name string) drainFixture {
	t.Helper()
	stats, err := os.ReadFile(filepath.Join("testdata", "drain", name+".stats.json"))
	require.NoError(t, err)
	dump, err := os.ReadFile(filepath.Join("testdata", "drain", name+".config_dump.json"))
	require.NoError(t, err)
	return drainFixture{stats: stats, dump: dump}
}

type statEntry struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// withStats returns the stats body with name set to v, or removed when v < 0.
func withStats(t *testing.T, body []byte, set map[string]int64) []byte {
	t.Helper()
	var sb struct {
		Stats []statEntry `json:"stats"`
	}
	require.NoError(t, json.Unmarshal(body, &sb))
	var out []statEntry
	seen := map[string]bool{}
	for _, s := range sb.Stats {
		if v, ok := set[s.Name]; ok {
			seen[s.Name] = true
			if v < 0 {
				continue
			}
			s.Value = v
		}
		out = append(out, s)
	}
	for name := range set {
		require.True(t, seen[name], "fixture has no stat %s", name)
	}
	b, err := json.Marshal(map[string]any{"stats": out})
	require.NoError(t, err)
	return b
}

func fixtureGauges(t *testing.T, f drainFixture) (drainGauges, error) {
	t.Helper()
	prefixes, err := listenerStatPrefixes(f.dump)
	require.NoError(t, err)
	return drainGaugesFrom(f.stats, prefixes)
}

const (
	httpListener = "listener.0.0.0.0_10080."
	tcpListener  = "listener.0.0.0.0_10443."
	httpHCM      = "http.http."
)

func TestIdleExitListenerPrefixes(t *testing.T) {
	want := map[string]bool{"0.0.0.0_10080": true, "0.0.0.0_10443": true}
	for _, name := range []string{"mixed_idle", "h1only_draining", "replaced_idle", "replaced_busy"} {
		t.Run(name, func(t *testing.T) {
			got, err := listenerStatPrefixes(loadDrainFixture(t, name).dump)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}

	t.Run("active and draining share a prefix", func(t *testing.T) {
		var d listenersDump
		require.NoError(t, json.Unmarshal(loadDrainFixture(t, "replaced_idle").dump, &d))
		require.Len(t, d.Configs, 2)
		assert.NotNil(t, d.Configs[0].ActiveState)
		assert.NotNil(t, d.Configs[0].DrainingState)
	})

	t.Run("stat_prefix, internal and IPv6", func(t *testing.T) {
		body := `{"configs":[
			{"@type":"` + dynamicListenerType + `","name":"a","active_state":{"listener":{"name":"a","stat_prefix":"edge:1","address":{"socket_address":{"address":"0.0.0.0","port_value":1}}}}},
			{"@type":"` + dynamicListenerType + `","name":"b","warming_state":{"listener":{"name":"b"}}},
			{"@type":"` + dynamicListenerType + `","name":"c","active_state":{"listener":{"name":"c","internal_listener":{}}}},
			{"@type":"` + dynamicListenerType + `","name":"d","draining_state":{"listener":{"name":"d","address":{"socket_address":{"address":"::","port_value":443}}}}}]}`
		got, err := listenerStatPrefixes([]byte(body))
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"edge_1": true, "envoy_internal_c": true, "[__]_443": true}, got)
	})

	t.Run("no dynamic listeners", func(t *testing.T) {
		got, err := listenerStatPrefixes([]byte(`{}`))
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	for name, body := range map[string]string{
		"not json":           `stats`,
		"unexpected type":    `{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump"}]}`,
		"state no listener":  `{"configs":[{"@type":"` + dynamicListenerType + `","name":"a","active_state":{}}]}`,
		"no socket address":  `{"configs":[{"@type":"` + dynamicListenerType + `","name":"a","active_state":{"listener":{"name":"a"}}}]}`,
		"hostname address":   `{"configs":[{"@type":"` + dynamicListenerType + `","name":"a","active_state":{"listener":{"name":"a","address":{"socket_address":{"address":"localhost","port_value":1}}}}}]}`,
		"configs not a list": `{"configs":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := listenerStatPrefixes([]byte(body))
			assert.Error(t, err)
		})
	}
}

func TestIdleExitGauges(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		set     map[string]int64
		want    drainGauges
		idle    bool
	}{{
		name:    "mixed protocol, idle, admin connection open",
		fixture: "mixed_idle",
		want:    drainGauges{RqTotal: 2},
		idle:    true,
	}, {
		name:    "HTTP/1 only, draining, no http2 stats",
		fixture: "h1only_draining",
		want:    drainGauges{RqTotal: 4},
		idle:    true,
	}, {
		name:    "active and draining generation, idle",
		fixture: "replaced_idle",
		want:    drainGauges{RqTotal: 4},
		idle:    true,
	}, {
		name:    "TCP proxy connection and tls_inspector connection open",
		fixture: "mixed_busy",
		want:    drainGauges{RqTotal: 4, HCMCx: 2, ListenerCx: 3, PreCx: 1},
	}, {
		name:    "active and draining generation, busy",
		fixture: "replaced_busy",
		want:    drainGauges{RqTotal: 4, HCMCx: 2, ListenerCx: 3, PreCx: 1},
	}, {
		name:    "socket in listener filters",
		fixture: "mixed_idle",
		set:     map[string]int64{tcpListener + "downstream_pre_cx_active": 1},
		want:    drainGauges{RqTotal: 2, PreCx: 1},
	}, {
		name:    "listener connection without HCM connection",
		fixture: "mixed_idle",
		set:     map[string]int64{tcpListener + "downstream_cx_active": 1},
		want:    drainGauges{RqTotal: 2, ListenerCx: 1},
	}, {
		name:    "idle HTTP connections",
		fixture: "mixed_idle",
		set:     map[string]int64{httpListener + "downstream_cx_active": 2, httpHCM + "downstream_cx_active": 2},
		want:    drainGauges{RqTotal: 2, ListenerCx: 2, HCMCx: 2},
		idle:    true,
	}, {
		name:    "active request",
		fixture: "h1only_draining",
		set:     map[string]int64{httpListener + "downstream_cx_active": 1, httpHCM + "downstream_cx_active": 1, httpHCM + "downstream_rq_active": 1},
		want:    drainGauges{RqTotal: 4, RqActive: 1, ListenerCx: 1, HCMCx: 1},
	}, {
		name:    "HCM response bytes buffered",
		fixture: "mixed_idle",
		set:     map[string]int64{httpHCM + "downstream_cx_tx_bytes_buffered": 4096},
		want:    drainGauges{RqTotal: 2, TxBuffered: 4096},
	}, {
		name:    "tcp_proxy bytes buffered",
		fixture: "mixed_idle",
		set:     map[string]int64{"tcp.passthrough.downstream_cx_tx_bytes_buffered": 10},
		want:    drainGauges{RqTotal: 2, TxBuffered: 10},
	}, {
		name:    "admin bytes buffered are ignored",
		fixture: "mixed_idle",
		set:     map[string]int64{"http.admin.downstream_cx_tx_bytes_buffered": 4096},
		want:    drainGauges{RqTotal: 2},
		idle:    true,
	}, {
		name:    "per-worker gauges are not summed",
		fixture: "mixed_idle",
		set:     map[string]int64{httpListener + "worker_0.downstream_cx_active": 7},
		want:    drainGauges{RqTotal: 2},
		idle:    true,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := loadDrainFixture(t, tc.fixture)
			if tc.set != nil {
				f.stats = withStats(t, f.stats, tc.set)
			}
			got, err := fixtureGauges(t, f)
			require.NoError(t, err)
			if drainCheckTxBuffered {
				assert.Equal(t, tc.want, got)
				assert.Equal(t, tc.idle, got.idle())
			}
		})
	}
}

func TestIdleExitMandatoryStats(t *testing.T) {
	mandatory := []string{
		httpListener + "downstream_cx_active",
		httpListener + "downstream_pre_cx_active",
		tcpListener + "downstream_cx_active",
		tcpListener + "downstream_pre_cx_active",
		httpHCM + "downstream_rq_active",
		httpHCM + "downstream_rq_total",
		httpHCM + "downstream_cx_active",
		httpHCM + "downstream_cx_tx_bytes_buffered",
	}
	for _, fixture := range []string{"mixed_idle", "h1only_draining", "replaced_idle"} {
		for _, stat := range mandatory {
			t.Run(fixture+"/"+stat, func(t *testing.T) {
				f := loadDrainFixture(t, fixture)
				f.stats = withStats(t, f.stats, map[string]int64{stat: -1})
				_, err := fixtureGauges(t, f)
				assert.Error(t, err)
			})
		}
	}

	t.Run("whole listener prefix missing", func(t *testing.T) {
		f := loadDrainFixture(t, "mixed_idle")
		f.stats = withStats(t, f.stats, map[string]int64{
			tcpListener + "downstream_cx_active":     -1,
			tcpListener + "downstream_pre_cx_active": -1,
		})
		_, err := fixtureGauges(t, f)
		assert.ErrorContains(t, err, "listener.0.0.0.0_10443")
	})

	t.Run("no dynamic listeners while an HCM exists", func(t *testing.T) {
		_, err := drainGaugesFrom(loadDrainFixture(t, "mixed_idle").stats, map[string]bool{})
		assert.Error(t, err)
	})

	t.Run("listener outside the config dump is summed", func(t *testing.T) {
		f := loadDrainFixture(t, "mixed_idle")
		got, err := drainGaugesFrom(f.stats, map[string]bool{"0.0.0.0_10080": true})
		require.NoError(t, err)
		require.True(t, got.idle())

		f.stats = withStats(t, f.stats, map[string]int64{tcpListener + "downstream_cx_active": 1})
		got, err = drainGaugesFrom(f.stats, map[string]bool{"0.0.0.0_10080": true})
		require.NoError(t, err)
		assert.Equal(t, int64(1), got.ListenerCx)
		assert.False(t, got.idle(), "a connection on it blocks the idle exit")
	})

	t.Run("not json", func(t *testing.T) {
		_, err := drainGaugesFrom([]byte("server.uptime: 1"), nil)
		assert.Error(t, err)
	})
}

func TestIdleExitReadyListener(t *testing.T) {
	const (
		readyListener = "listener." + readyListenerScope + "."
		readyHCM      = "http." + readyHCMScope + "."
	)

	t.Run("matches the bootstrap", func(t *testing.T) {
		cfg, err := bootstrap.GetRenderedBootstrapConfig()
		require.NoError(t, err)
		var bs struct {
			StaticResources struct {
				Listeners []struct {
					dumpedListener
					FilterChains []struct {
						Filters []struct {
							TypedConfig struct {
								StatPrefix string `json:"stat_prefix"`
							} `json:"typed_config"`
						} `json:"filters"`
					} `json:"filter_chains"`
				} `json:"listeners"`
			} `json:"static_resources"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(cfg), &bs))
		require.Len(t, bs.StaticResources.Listeners, 1)
		l := bs.StaticResources.Listeners[0]
		scope, err := listenerStatScope(&l.dumpedListener)
		require.NoError(t, err)
		assert.Equal(t, readyListenerScope, scope)
		assert.Equal(t, readyHCMScope, l.FilterChains[0].Filters[0].TypedConfig.StatPrefix)
	})

	t.Run("static, so never in the dynamic listeners", func(t *testing.T) {
		prefixes, err := listenerStatPrefixes(loadDrainFixture(t, "ready_probed_a").dump)
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"0.0.0.0_10080": true, "0.0.0.0_10443": true}, prefixes)
	})

	t.Run("probes between polls are not requests", func(t *testing.T) {
		a, err := fixtureGauges(t, loadDrainFixture(t, "ready_probed_a"))
		require.NoError(t, err)
		b, err := fixtureGauges(t, loadDrainFixture(t, "ready_probed_b"))
		require.NoError(t, err)
		assert.True(t, a.idle())
		assert.True(t, b.idle())
		assert.Equal(t, a.RqTotal, b.RqTotal, "the captures differ by six probes")
	})

	t.Run("a probe in flight is not a connection", func(t *testing.T) {
		f := loadDrainFixture(t, "ready_probed_a")
		f.stats = withStats(t, f.stats, map[string]int64{
			readyListener + "downstream_cx_active": 1,
			readyHCM + "downstream_cx_active":      1,
			readyHCM + "downstream_rq_active":      1,
		})
		got, err := fixtureGauges(t, f)
		require.NoError(t, err)
		assert.True(t, got.idle())
	})

	t.Run("a dynamic listener with that scope is counted", func(t *testing.T) {
		f := loadDrainFixture(t, "ready_probed_a")
		f.stats = withStats(t, f.stats, map[string]int64{readyListener + "downstream_cx_active": 1})
		got, err := drainGaugesFrom(f.stats, map[string]bool{
			"0.0.0.0_10080": true, "0.0.0.0_10443": true, readyListenerScope: true,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(1), got.ListenerCx)
		assert.False(t, got.idle())
	})
}

func TestIdleExitUDPListener(t *testing.T) {
	f := loadDrainFixture(t, "udp_session")

	t.Run("the gauges miss the UDP session", func(t *testing.T) {
		got, err := drainGaugesFrom(f.stats, map[string]bool{
			"0.0.0.0_10080": true, "0.0.0.0_10443": true, "0.0.0.0_10053": true,
		})
		require.NoError(t, err)
		assert.True(t, got.idle(), "udp.udp.downstream_sess_active is 1 in this capture")
	})

	t.Run("a UDP listener fails the prefixes", func(t *testing.T) {
		_, err := listenerStatPrefixes(f.dump)
		assert.ErrorIs(t, err, errUDPListener)
	})

	t.Run("udp_listener_config alone marks it", func(t *testing.T) {
		dump := strings.Replace(string(f.dump), `"protocol": "UDP",`, "", 1)
		require.NotEqual(t, string(f.dump), dump)
		_, err := listenerStatPrefixes([]byte(dump))
		assert.ErrorIs(t, err, errUDPListener)
	})
}

func TestIdleExitTracker(t *testing.T) {
	t0 := time.Now()
	at := func(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }
	idle := drainGauges{RqTotal: 5}
	busy := drainGauges{RqTotal: 5, RqActive: 1}

	tr := idleTracker{quiet: 10 * time.Second}
	for s := 0; s < 10; s++ {
		require.False(t, tr.observe(at(float64(s)), idle, nil), "second %d", s)
	}
	assert.True(t, tr.observe(at(10), idle, nil))

	tr = idleTracker{quiet: 10 * time.Second}
	tr.observe(at(0), idle, nil)
	assert.False(t, tr.observe(at(5), drainGauges{RqTotal: 6}, nil), "a new request restarts Q")
	assert.False(t, tr.observe(at(14), drainGauges{RqTotal: 6}, nil))
	assert.True(t, tr.observe(at(15), drainGauges{RqTotal: 6}, nil))

	tr = idleTracker{quiet: 10 * time.Second}
	tr.observe(at(0), idle, nil)
	assert.False(t, tr.observe(at(5), busy, nil))
	assert.False(t, tr.observe(at(14), idle, nil))
	assert.True(t, tr.observe(at(24), idle, nil))

	tr = idleTracker{quiet: 10 * time.Second}
	tr.observe(at(0), idle, nil)
	assert.False(t, tr.observe(at(5), idle, assert.AnError), "a fetch error restarts Q")
	assert.False(t, tr.observe(at(10), idle, nil))
	assert.True(t, tr.observe(at(20), idle, nil))
}

// fakeAdmin serves the Envoy admin API from switchable fixture bodies.
type fakeAdmin struct {
	*httptest.Server

	mu    sync.Mutex
	stats []byte
	dump  []byte
	fail  bool
	calls map[string]int
	// block makes every request hang until the channel closes.
	block chan struct{}
	// firstPollDelay delays the first config_dump GET.
	firstPollDelay time.Duration
	// firstStatsAt is when the first stats response was written.
	firstStatsAt time.Time
	// onQuit runs on quitquitquit.
	onQuit func()
}

func newFakeAdmin(t *testing.T, f drainFixture) *fakeAdmin {
	a := &fakeAdmin{stats: f.stats, dump: f.dump, calls: map[string]int{}}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(func() {
		a.mu.Lock()
		if a.block != nil {
			close(a.block)
			a.block = nil
		}
		a.mu.Unlock()
		a.Server.Close()
	})
	return a
}

func (a *fakeAdmin) host() string { return strings.TrimPrefix(a.URL, "http://") }

func (a *fakeAdmin) set(f drainFixture, fail bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats, a.dump, a.fail = f.stats, f.dump, fail
}

func (a *fakeAdmin) count(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[path]
}

func (a *fakeAdmin) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.calls[r.URL.Path]++
	stats, dump, fail, block, onQuit := a.stats, a.dump, a.fail, a.block, a.onQuit
	var delay time.Duration
	if r.URL.Path == "/config_dump" && a.calls[r.URL.Path] == 1 {
		delay = a.firstPollDelay
	}
	a.mu.Unlock()
	if block != nil {
		<-block
		return
	}
	time.Sleep(delay)
	switch {
	case fail && r.Method == http.MethodGet:
		http.Error(w, "boom", http.StatusInternalServerError)
	case r.URL.Path == "/stats":
		if r.URL.Query().Get("filter") != drainStatsFilter || r.URL.Query().Get("format") != "json" {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		w.Write(stats)
		a.mu.Lock()
		if a.firstStatsAt.IsZero() {
			a.firstStatsAt = time.Now()
		}
		a.mu.Unlock()
	case r.URL.Path == "/config_dump":
		if r.URL.Query().Get("resource") != "dynamic_listeners" {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		w.Write(dump)
	case r.URL.Path == "/quitquitquit":
		if onQuit != nil {
			onQuit()
		}
	}
}

func fastTimeouts() shutdownTimeouts {
	return shutdownTimeouts{
		admin:     200 * time.Millisecond,
		stats:     200 * time.Millisecond,
		poll:      20 * time.Millisecond,
		quitWait:  300 * time.Millisecond,
		killWait:  300 * time.Millisecond,
		telemetry: 200 * time.Millisecond,
	}
}

// runDrain runs the drain loop against admin and returns whether it ended idle
// and when.
func runDrain(t *testing.T, a *fakeAdmin, quiet, minDrain, timeout time.Duration) (bool, time.Duration) {
	t.Helper()
	g := newGeneration()
	c := shutdownConfig{
		admin:        adminClient{host: a.host(), timeouts: fastTimeouts()},
		minDrainTime: minDrain,
		quiet:        quiet,
		timeouts:     fastTimeouts(),
	}
	t0 := time.Now()
	idle := drainIdle(g, c, t0, func() time.Time { return t0.Add(timeout) })
	return idle, time.Since(t0)
}

func TestIdleExitDrain(t *testing.T) {
	const quiet = 200 * time.Millisecond

	t.Run("HTTP/1 only exits after Q", func(t *testing.T) {
		a := newFakeAdmin(t, loadDrainFixture(t, "h1only_draining"))
		idle, took := runDrain(t, a, quiet, 100*time.Millisecond, 5*time.Second)
		assert.True(t, idle)
		assert.GreaterOrEqual(t, took, 300*time.Millisecond)
		assert.Less(t, took, 2*time.Second)
	})

	t.Run("mixed protocol with admin connection exits after Q", func(t *testing.T) {
		a := newFakeAdmin(t, loadDrainFixture(t, "mixed_idle"))
		idle, took := runDrain(t, a, quiet, 0, 5*time.Second)
		assert.True(t, idle)
		assert.GreaterOrEqual(t, took, quiet)
	})

	t.Run("active and draining generation exits after Q", func(t *testing.T) {
		a := newFakeAdmin(t, loadDrainFixture(t, "replaced_idle"))
		idle, _ := runDrain(t, a, quiet, 0, 5*time.Second)
		assert.True(t, idle)
	})

	t.Run("busy never exits", func(t *testing.T) {
		a := newFakeAdmin(t, loadDrainFixture(t, "mixed_busy"))
		idle, took := runDrain(t, a, quiet, 0, time.Second)
		assert.False(t, idle)
		assert.GreaterOrEqual(t, took, time.Second)
	})

	t.Run("Q zero disables the idle exit", func(t *testing.T) {
		a := newFakeAdmin(t, loadDrainFixture(t, "mixed_idle"))
		idle, took := runDrain(t, a, 0, 0, 500*time.Millisecond)
		assert.False(t, idle)
		assert.GreaterOrEqual(t, took, 500*time.Millisecond)
		assert.Zero(t, a.count("/stats"))
	})

	t.Run("buffered bytes hold the exit until flushed", func(t *testing.T) {
		if !drainCheckTxBuffered {
			t.Skip("a4nobuffer build")
		}
		base := loadDrainFixture(t, "h1only_draining")
		buffered := base
		buffered.stats = withStats(t, base.stats, map[string]int64{
			httpListener + "downstream_cx_active":       1,
			httpHCM + "downstream_cx_active":            1,
			httpHCM + "downstream_cx_tx_bytes_buffered": 786432,
		})
		a := newFakeAdmin(t, buffered)
		go func() {
			time.Sleep(3 * quiet)
			a.set(base, false)
		}()
		idle, took := runDrain(t, a, quiet, 0, 5*time.Second)
		assert.True(t, idle)
		assert.GreaterOrEqual(t, took, 4*quiet)
	})

	t.Run("fetch error resets Q", func(t *testing.T) {
		f := loadDrainFixture(t, "h1only_draining")
		a := newFakeAdmin(t, f)
		go func() {
			time.Sleep(quiet / 2)
			a.set(f, true)
			time.Sleep(quiet)
			a.set(f, false)
		}()
		idle, took := runDrain(t, a, quiet, 0, 5*time.Second)
		assert.True(t, idle)
		assert.GreaterOrEqual(t, took, quiet/2+quiet+quiet)
	})

	t.Run("config dump error never exits", func(t *testing.T) {
		f := loadDrainFixture(t, "h1only_draining")
		f.dump = []byte(`{"configs":[{"@type":"bogus"}]}`)
		a := newFakeAdmin(t, f)
		idle, _ := runDrain(t, a, quiet, 0, 600*time.Millisecond)
		assert.False(t, idle)
	})

	t.Run("missing mandatory stat never exits", func(t *testing.T) {
		f := loadDrainFixture(t, "h1only_draining")
		f.stats = withStats(t, f.stats, map[string]int64{tcpListener + "downstream_cx_active": -1})
		a := newFakeAdmin(t, f)
		idle, _ := runDrain(t, a, quiet, 0, 600*time.Millisecond)
		assert.False(t, idle)
	})

	t.Run("Q counts from the first completed sample", func(t *testing.T) {
		a := newFakeAdmin(t, loadDrainFixture(t, "mixed_idle"))
		a.firstPollDelay = 150 * time.Millisecond
		idle, _ := runDrain(t, a, quiet, 0, 5*time.Second)
		exitAt := time.Now()
		require.True(t, idle)
		a.mu.Lock()
		defer a.mu.Unlock()
		assert.GreaterOrEqual(t, exitAt.Sub(a.firstStatsAt), quiet)
	})

	t.Run("readiness probes during Q do not reset it", func(t *testing.T) {
		base := loadDrainFixture(t, "ready_probed_a")
		probed := make([]drainFixture, 100)
		for i := range probed {
			probed[i] = base
			probed[i].stats = withStats(t, base.stats, map[string]int64{"http." + readyHCMScope + ".downstream_rq_total": int64(100 + i)})
		}
		a := newFakeAdmin(t, base)
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			for i := 0; ; i++ {
				a.set(probed[i%len(probed)], false)
				select {
				case <-stop:
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		}()
		idle, took := runDrain(t, a, quiet, 0, 3*time.Second)
		assert.True(t, idle)
		assert.Less(t, took, time.Second)
	})

	t.Run("a UDP listener disables the idle exit", func(t *testing.T) {
		a := newFakeAdmin(t, loadDrainFixture(t, "udp_session"))
		idle, took := runDrain(t, a, quiet, 0, 600*time.Millisecond)
		assert.False(t, idle)
		assert.GreaterOrEqual(t, took, 600*time.Millisecond)
		assert.Equal(t, 1, a.count("/config_dump"), "no polls after the first")
	})

	t.Run("min drain time gates the exit", func(t *testing.T) {
		a := newFakeAdmin(t, loadDrainFixture(t, "mixed_idle"))
		idle, took := runDrain(t, a, quiet, 500*time.Millisecond, 5*time.Second)
		assert.True(t, idle)
		assert.GreaterOrEqual(t, took, 500*time.Millisecond+quiet)
	})
}
