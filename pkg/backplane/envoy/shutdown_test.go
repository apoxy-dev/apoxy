package envoy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fakeEnvoyModeEnv   = "FAKE_ENVOY_MODE"
	fakeEnvoyStartsEnv = "FAKE_ENVOY_STARTS"
)

// TestMain doubles as the fake Envoy binary the runtime starts.
func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeEnvoyModeEnv); mode != "" {
		fakeEnvoy(mode)
		return
	}
	os.Exit(m.Run())
}

// fakeEnvoy exits 0 on SIGTERM, or 3 after "exit-after=<duration>". In
// "ignore-term" mode only SIGKILL stops it.
func fakeEnvoy(mode string) {
	if p := os.Getenv(fakeEnvoyStartsEnv); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			f.WriteString("start\n")
			f.Close()
		}
	}
	if mode == "ignore-term" {
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
		time.Sleep(time.Hour)
		return
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	var after <-chan time.Time
	if d, ok := strings.CutPrefix(mode, "exit-after="); ok {
		dur, _ := time.ParseDuration(d)
		after = time.After(dur)
	}
	select {
	case <-sig:
		os.Exit(0)
	case <-after:
		os.Exit(3)
	}
}

type fakeRelease struct {
	download func(context.Context) (io.ReadCloser, error)
}

func (fakeRelease) String() string { return "fake" }

func (f fakeRelease) DownloadBinary(ctx context.Context) (io.ReadCloser, error) {
	if f.download == nil {
		return nil, errors.New("no download")
	}
	return f.download(ctx)
}

type testRuntime struct {
	*Runtime
	admin  *fakeAdmin
	starts string

	mu     sync.Mutex
	phases []DrainPhase
}

func (tr *testRuntime) phase(p DrainPhase) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.phases = append(tr.phases, p)
}

func (tr *testRuntime) drainPhases() []DrainPhase {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]DrainPhase(nil), tr.phases...)
}

func (tr *testRuntime) startCount() int {
	b, err := os.ReadFile(tr.starts)
	if err != nil {
		return 0
	}
	return bytes.Count(b, []byte("start\n"))
}

func (tr *testRuntime) pid() int {
	tr.Runtime.mu.RLock()
	defer tr.Runtime.mu.RUnlock()
	if tr.Runtime.cmd == nil || tr.Runtime.cmd.Process == nil {
		return 0
	}
	return tr.Runtime.cmd.Process.Pid
}

type runtimeOpts struct {
	mode         string
	fixture      string
	drainTimeout time.Duration
	minDrain     time.Duration
	quiet        time.Duration
	extra        []Option
}

func newTestRuntime(t *testing.T, o runtimeOpts) *testRuntime {
	t.Helper()
	if o.mode == "" {
		o.mode = "serve"
	}
	if o.fixture == "" {
		o.fixture = "h1only_draining"
	}
	tr := &testRuntime{
		Runtime: &Runtime{
			EnvoyPath: os.Args[0],
			Release:   fakeRelease{},
			timeouts:  fastTimeouts(),
		},
		admin:  newFakeAdmin(t, loadDrainFixture(t, o.fixture)),
		starts: filepath.Join(t.TempDir(), "starts"),
	}
	tr.admin.onQuit = func() {
		if pid := tr.pid(); pid != 0 {
			syscall.Kill(pid, syscall.SIGTERM)
		}
	}
	t.Setenv(fakeEnvoyModeEnv, o.mode)
	// The race runtime sleeps 1s in os.Exit by default.
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	t.Setenv(fakeEnvoyStartsEnv, tr.starts)
	t.Cleanup(func() { tr.KillEnvoy() })
	return tr
}

func (tr *testRuntime) start(t *testing.T, o runtimeOpts) {
	t.Helper()
	if o.drainTimeout == 0 {
		o.drainTimeout = 10 * time.Second
	}
	opts := []Option{
		WithAdminHost(tr.admin.host()),
		WithDrainTimeout(&o.drainTimeout),
		WithMinDrainTime(&o.minDrain),
		WithDrainIdleExitQuietPeriod(o.quiet),
		WithDrainPhaseHook(tr.phase),
	}
	require.NoError(t, tr.Start(context.Background(), append(opts, o.extra...)...))
}

// waitRunning waits until the n-th fake Envoy runs its main.
func (tr *testRuntime) waitRunning(t *testing.T, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return tr.RuntimeStatus().Running && tr.startCount() >= n
	}, 5*time.Second, 5*time.Millisecond)
}

func waitDone(t *testing.T, ch <-chan struct{}, d time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("shutdown did not finish within %s", d)
	}
	return time.Since(start)
}

func TestShutdownConcurrentCallsDrainOnce(t *testing.T) {
	o := runtimeOpts{quiet: 100 * time.Millisecond}
	tr := newTestRuntime(t, o)
	tr.start(t, o)
	tr.waitRunning(t, 1)

	var wg sync.WaitGroup
	dones := make(chan (<-chan struct{}), 16)
	errs := make(chan error, 4)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dones <- tr.BeginShutdown()
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- tr.Shutdown(context.Background())
		}()
	}
	wg.Wait()
	close(dones)
	close(errs)

	var first <-chan struct{}
	for d := range dones {
		if first == nil {
			first = d
		}
		assert.Equal(t, first, d, "every caller shares one shutdown")
		assert.True(t, isClosed(d))
	}
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, 1, tr.admin.count("/healthcheck/fail"))
	assert.Equal(t, 1, tr.admin.count("/drain_listeners"))
	assert.Equal(t, 1, tr.admin.count("/quitquitquit"))
	assert.Equal(t, []DrainPhase{DrainPhaseServing, DrainPhaseDraining, DrainPhaseIdle, DrainPhaseStopping}, tr.drainPhases())
	assert.Equal(t, 1, tr.startCount())
	assert.False(t, tr.RuntimeStatus().Running)
	assert.NotNil(t, tr.RuntimeStatus().ProcState)
}

func TestShutdownNoGeneration(t *testing.T) {
	r := &Runtime{}
	assert.True(t, isClosed(r.BeginShutdown()))
	stopped, done := r.BeginShutdownBy(time.Now())
	assert.True(t, isClosed(stopped))
	assert.True(t, isClosed(done))
	assert.NoError(t, r.Shutdown(context.Background()))
	assert.NoError(t, r.KillEnvoy())
}

func TestShutdownDuringStartup(t *testing.T) {
	o := runtimeOpts{quiet: 100 * time.Millisecond}
	tr := newTestRuntime(t, o)
	tr.EnvoyPath = filepath.Join(t.TempDir(), "envoy")
	downloading := make(chan struct{})
	release := make(chan struct{})
	tr.Release = fakeRelease{download: func(context.Context) (io.ReadCloser, error) {
		close(downloading)
		<-release
		return os.Open(os.Args[0])
	}}

	started := make(chan error, 1)
	go func() {
		started <- tr.Start(context.Background(),
			WithAdminHost(tr.admin.host()), WithDrainIdleExitQuietPeriod(o.quiet), WithDrainPhaseHook(tr.phase))
	}()
	<-downloading

	done := tr.BeginShutdown()
	close(release)
	require.NoError(t, <-started)
	waitDone(t, done, 5*time.Second)

	// No Envoy ever ran and the generation never reached it.
	time.Sleep(200 * time.Millisecond)
	assert.Zero(t, tr.startCount())
	assert.Zero(t, tr.admin.count("/healthcheck/fail"))
	assert.False(t, tr.RuntimeStatus().Running)
	assert.False(t, tr.RuntimeStatus().Starting)
}

func TestShutdownNoRestartMidDrain(t *testing.T) {
	t.Run("supervisor restarts a crashed envoy while serving", func(t *testing.T) {
		o := runtimeOpts{mode: "exit-after=50ms"}
		tr := newTestRuntime(t, o)
		tr.start(t, o)
		require.Eventually(t, func() bool { return tr.startCount() >= 3 }, 5*time.Second, 10*time.Millisecond)
		waitDone(t, tr.BeginShutdown(), 5*time.Second)
	})

	t.Run("crash during the drain ends it without a restart", func(t *testing.T) {
		o := runtimeOpts{mode: "exit-after=700ms", minDrain: 10 * time.Second, quiet: 100 * time.Millisecond}
		tr := newTestRuntime(t, o)
		tr.start(t, o)
		tr.waitRunning(t, 1)

		took := waitDone(t, tr.BeginShutdown(), 5*time.Second)
		assert.Less(t, took, 3*time.Second, "the drain must not run to its timeout")
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 1, tr.startCount())
		assert.Zero(t, tr.admin.count("/quitquitquit"))
		assert.False(t, tr.RuntimeStatus().Running)
	})

	t.Run("kill during the drain ends it without a restart", func(t *testing.T) {
		o := runtimeOpts{minDrain: 10 * time.Second, quiet: 100 * time.Millisecond}
		tr := newTestRuntime(t, o)
		tr.start(t, o)
		tr.waitRunning(t, 1)

		done := tr.BeginShutdown()
		require.Eventually(t, func() bool { return tr.admin.count("/drain_listeners") == 1 }, 5*time.Second, 5*time.Millisecond)
		require.NoError(t, tr.KillEnvoy())
		took := waitDone(t, done, 5*time.Second)
		assert.Less(t, took, 3*time.Second)
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 1, tr.startCount())
	})
}

func TestShutdownRestartAfterDone(t *testing.T) {
	o := runtimeOpts{quiet: 100 * time.Millisecond}
	tr := newTestRuntime(t, o)
	tr.start(t, o)
	tr.waitRunning(t, 1)
	require.NoError(t, tr.Shutdown(context.Background()))

	tr.start(t, o)
	tr.waitRunning(t, 2)
	assert.Equal(t, 2, tr.startCount())
	require.NoError(t, tr.Shutdown(context.Background()))
	assert.Equal(t, 2, tr.admin.count("/healthcheck/fail"))
	assert.Equal(t, 2, tr.admin.count("/quitquitquit"))
}

func TestShutdownAdminHang(t *testing.T) {
	o := runtimeOpts{quiet: 100 * time.Millisecond, drainTimeout: 500 * time.Millisecond}
	tr := newTestRuntime(t, o)
	tr.start(t, o)
	tr.waitRunning(t, 1)
	tr.admin.mu.Lock()
	tr.admin.block = make(chan struct{})
	tr.admin.mu.Unlock()

	start := time.Now()
	err := tr.Shutdown(context.Background())
	took := time.Since(start)
	assert.ErrorIs(t, err, errEnvoyKilled)
	// healthcheck + drain_listeners + drain + quitquitquit + quit wait + kill wait.
	assert.Less(t, took, 2500*time.Millisecond)
	assert.False(t, tr.RuntimeStatus().Running)
	assert.Equal(t, 1, tr.startCount())
}

func TestShutdownCollectorHang(t *testing.T) {
	o := runtimeOpts{quiet: 100 * time.Millisecond}
	tr := newTestRuntime(t, o)
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	tr.stopTelemetryFn = func(context.Context) error {
		<-hang
		return nil
	}
	tr.start(t, o)
	tr.waitRunning(t, 1)

	stopped, done := tr.BeginShutdownBy(time.Time{})
	waitDone(t, stopped, 5*time.Second)
	assert.False(t, isClosed(done), "telemetry still stopping")
	took := waitDone(t, done, 5*time.Second)
	assert.GreaterOrEqual(t, took, 150*time.Millisecond)
	assert.Less(t, took, time.Second)
}

func TestShutdownDrainEndCap(t *testing.T) {
	o := runtimeOpts{quiet: 0}
	tr := newTestRuntime(t, o)
	tr.start(t, o)
	tr.waitRunning(t, 1)

	start := time.Now()
	_, done := tr.BeginShutdownBy(start.Add(300 * time.Millisecond))
	took := waitDone(t, done, 5*time.Second)
	assert.GreaterOrEqual(t, took, 300*time.Millisecond)
	assert.Less(t, took, 2*time.Second, "the cap overrides the 10s drain timeout")
}

func TestShutdownIdleExitTestPause(t *testing.T) {
	o := runtimeOpts{quiet: 100 * time.Millisecond, extra: []Option{WithDrainIdleExitTestPause(400 * time.Millisecond)}}
	tr := newTestRuntime(t, o)
	var mu sync.Mutex
	at := map[DrainPhase]time.Time{}
	o.extra = append(o.extra, WithDrainPhaseHook(func(p DrainPhase) {
		mu.Lock()
		defer mu.Unlock()
		at[p] = time.Now()
	}))
	tr.start(t, o)
	tr.waitRunning(t, 1)
	require.NoError(t, tr.Shutdown(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	require.Contains(t, at, DrainPhaseIdle)
	require.Contains(t, at, DrainPhaseStopping)
	assert.GreaterOrEqual(t, at[DrainPhaseStopping].Sub(at[DrainPhaseIdle]), 400*time.Millisecond)
}

func TestShutdownDeadlineTightens(t *testing.T) {
	for _, quiet := range []time.Duration{0, 100 * time.Millisecond} {
		t.Run("deletion then SIGTERM, quiet "+quiet.String(), func(t *testing.T) {
			o := runtimeOpts{quiet: quiet, minDrain: time.Second, fixture: "mixed_busy"}
			tr := newTestRuntime(t, o)
			tr.start(t, o)
			tr.waitRunning(t, 1)

			done := tr.BeginShutdown()
			time.Sleep(1200 * time.Millisecond)
			start := time.Now()
			stopped, done2 := tr.BeginShutdownBy(start.Add(50 * time.Millisecond))
			assert.Equal(t, done, done2)
			waitDone(t, stopped, 5*time.Second)
			took := time.Since(start)
			assert.GreaterOrEqual(t, took, 50*time.Millisecond)
			assert.Less(t, took, 500*time.Millisecond, "the drain ends at the cap, not the 10s timeout")
		})
	}

	t.Run("a later call never lengthens the drain", func(t *testing.T) {
		o := runtimeOpts{}
		tr := newTestRuntime(t, o)
		tr.start(t, o)
		tr.waitRunning(t, 1)

		start := time.Now()
		_, done := tr.BeginShutdownBy(start.Add(300 * time.Millisecond))
		tr.BeginShutdownBy(start.Add(5 * time.Second))
		tr.BeginShutdown()
		took := waitDone(t, done, 5*time.Second)
		assert.Less(t, took, 2*time.Second)
	})
}

func TestShutdownStopFailed(t *testing.T) {
	for name, kill := range map[string]func(*os.Process) error{
		"kill fails":          func(*os.Process) error { return errors.New("kill refused") },
		"exit wait times out": func(*os.Process) error { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			o := runtimeOpts{mode: "ignore-term", drainTimeout: 100 * time.Millisecond}
			tr := newTestRuntime(t, o)
			tr.killFn = kill
			tr.start(t, o)
			tr.waitRunning(t, 1)

			stopped, done := tr.BeginShutdownBy(time.Time{})
			waitDone(t, done, 5*time.Second)
			assert.False(t, isClosed(stopped), "envoy still runs")
			assert.Error(t, tr.Shutdown(context.Background()))
			assert.True(t, tr.RuntimeStatus().Running)

			require.NoError(t, tr.KillEnvoy())
			waitDone(t, stopped, 5*time.Second)
			assert.False(t, tr.RuntimeStatus().Running)
		})
	}
}

func TestShutdownFencesStart(t *testing.T) {
	o := runtimeOpts{quiet: 100 * time.Millisecond}
	tr := newTestRuntime(t, o)

	stopped, done := tr.BeginShutdownBy(time.Now().Add(time.Second))
	assert.True(t, isClosed(stopped))
	assert.True(t, isClosed(done))
	for i := 0; i < 3; i++ {
		opts := []Option{WithAdminHost(tr.admin.host()), WithDrainPhaseHook(tr.phase)}
		assert.ErrorIs(t, tr.Start(context.Background(), opts...), ErrShutDown)
	}
	time.Sleep(200 * time.Millisecond)
	assert.Zero(t, tr.startCount())
	assert.False(t, tr.RuntimeStatus().Running)
	assert.False(t, tr.RuntimeStatus().Starting)
	assert.Empty(t, tr.drainPhases())
}
