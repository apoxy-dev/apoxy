package envoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// DrainPhase is the progress of an Envoy shutdown.
type DrainPhase int

const (
	// DrainPhaseServing means no shutdown has started.
	DrainPhaseServing DrainPhase = iota
	// DrainPhaseDraining means the listeners drain.
	DrainPhaseDraining
	// DrainPhaseIdle means the drain ended because Envoy went idle.
	DrainPhaseIdle
	// DrainPhaseStopping means Envoy is being stopped.
	DrainPhaseStopping
	// DrainPhaseLeaving means Envoy stopped and the backplane leaves the K/V cluster.
	DrainPhaseLeaving
)

// shutdownTimeouts bound every step of a shutdown.
type shutdownTimeouts struct {
	admin     time.Duration // admin POSTs
	stats     time.Duration // admin GETs
	poll      time.Duration // drain poll period
	quitWait  time.Duration // exit wait after quitquitquit
	killWait  time.Duration // exit wait after SIGKILL
	telemetry time.Duration
}

var defaultShutdownTimeouts = shutdownTimeouts{
	admin:     time.Second,
	stats:     2 * time.Second,
	poll:      time.Second,
	quitWait:  2 * time.Second,
	killWait:  time.Second,
	telemetry: metricsFlushTimeout,
}

// ErrShutDown is returned by Start once the backplane began exiting.
var ErrShutDown = errors.New("envoy runtime shut down for good")

var (
	errShuttingDown = errors.New("envoy is shutting down")
	errEnvoyKilled  = errors.New("envoy process killed")
)

// generation is one Start of the runtime. It shuts down at most once.
type generation struct {
	stopCh chan struct{}
	once   sync.Once
	done   chan struct{}
	err    error
	// exited closes when the supervisor returns; no Envoy runs after that.
	exited     chan struct{}
	exitedOnce sync.Once
	// stopped closes once the Envoy exit is confirmed, never on a failed stop.
	stopped chan struct{}
	// tightened wakes the drain when drainEnd moves earlier.
	tightened chan struct{}

	// Guarded by Runtime.mu.
	shuttingDown bool
	cmd          *exec.Cmd
	// drainEnd is the earliest drain end a caller asked for, or zero.
	drainEnd time.Time
}

func newGeneration() *generation {
	return &generation{
		stopCh:    make(chan struct{}),
		done:      make(chan struct{}),
		exited:    make(chan struct{}),
		stopped:   make(chan struct{}),
		tightened: make(chan struct{}, 1),
	}
}

func (g *generation) closeExited() {
	g.exitedOnce.Do(func() { close(g.exited) })
}

func (g *generation) isDone() bool {
	return isClosed(g.done)
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// waitClosed reports whether ch closed within d.
func waitClosed(ch <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		return false
	}
}

var closedCh = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// BeginShutdown starts the shutdown of the current generation, once, and
// returns a channel that closes when it is done. It never blocks.
func (r *Runtime) BeginShutdown() <-chan struct{} {
	g := r.beginShutdown(time.Time{}, false)
	if g == nil {
		return closedCh
	}
	return g.done
}

// BeginShutdownBy also fences Start for good; callers share one shutdown and a later drainEnd only tightens.
func (r *Runtime) BeginShutdownBy(drainEnd time.Time) (stopped, done <-chan struct{}) {
	g := r.beginShutdown(drainEnd, true)
	if g == nil {
		return closedCh, closedCh
	}
	return g.stopped, g.done
}

func (r *Runtime) beginShutdown(drainEnd time.Time, fence bool) *generation {
	r.mu.Lock()
	if fence {
		r.fenced = true
	}
	g := r.gen
	if g == nil {
		r.mu.Unlock()
		return nil
	}
	g.shuttingDown = true
	if !drainEnd.IsZero() && (g.drainEnd.IsZero() || drainEnd.Before(g.drainEnd)) {
		g.drainEnd = drainEnd
		select {
		case g.tightened <- struct{}{}:
		default:
		}
	}
	r.mu.Unlock()

	g.once.Do(func() { go r.doShutdown(g) })
	return g
}

// Shutdown gracefully drains connections and shuts down the Envoy process.
func (r *Runtime) Shutdown(ctx context.Context) error {
	g := r.beginShutdown(time.Time{}, false)
	if g == nil {
		return nil
	}
	select {
	case <-g.done:
		return g.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// KillEnvoy sends SIGKILL to the last started Envoy process.
func (r *Runtime) KillEnvoy() error {
	r.mu.RLock()
	cmd := r.cmd
	r.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// DrainTimeout returns the drain timeout of the current configuration.
func (r *Runtime) DrainTimeout() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.drainTimeout == nil {
		return defaultDrainTimeoutSeconds * time.Second
	}
	return *r.drainTimeout
}

// shutdownConfig is the runtime configuration a shutdown reads once.
type shutdownConfig struct {
	cmd          *exec.Cmd
	admin        adminClient
	drainTimeout time.Duration
	minDrainTime time.Duration
	quiet        time.Duration
	testPause    time.Duration
	timeouts     shutdownTimeouts
	phase        func(DrainPhase)
	stopTel      func(context.Context) error
	kill         func(*os.Process) error
	lastExit     func() error
}

func (r *Runtime) shutdownConfig(g *generation) shutdownConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c := shutdownConfig{
		cmd:          g.cmd,
		admin:        adminClient{host: r.adminHost, timeouts: r.timeouts},
		drainTimeout: *r.drainTimeout,
		minDrainTime: *r.minDrainTime,
		quiet:        r.idleQuietPeriod,
		testPause:    r.idleTestPause,
		timeouts:     r.timeouts,
		phase:        r.phaseHook,
		stopTel:      r.stopTelemetryFn,
		kill:         r.killFn,
		lastExit:     r.lastExitError,
	}
	if c.stopTel == nil {
		c.stopTel = r.shutdownTelemetry
	}
	if c.phase == nil {
		c.phase = func(DrainPhase) {}
	}
	if c.kill == nil {
		c.kill = (*os.Process).Kill
	}
	return c
}

func (r *Runtime) doShutdown(g *generation) {
	defer close(g.done)
	t0 := time.Now()
	close(g.stopCh)
	c := r.shutdownConfig(g)

	log.Infof("shutting down envoy with drain timeout %s", c.drainTimeout)

	end := func() time.Time {
		r.mu.RLock()
		defer r.mu.RUnlock()
		end := t0.Add(c.drainTimeout)
		if !g.drainEnd.IsZero() && g.drainEnd.Before(end) {
			end = g.drainEnd
		}
		return end
	}

	c.phase(DrainPhaseDraining)
	if c.cmd != nil && !isClosed(g.exited) {
		if err := c.admin.post("healthcheck/fail"); err != nil {
			log.Errorf("error failing active health checks: %v", err)
		}
		if err := c.admin.post("drain_listeners?graceful&skip_exit"); err != nil {
			log.Errorf("error initiating graceful drain: %v", err)
		}
		if drainIdle(g, c, t0, end) {
			c.phase(DrainPhaseIdle)
			if c.testPause > 0 {
				log.Infof("holding for test pause %s", c.testPause)
				waitClosed(g.exited, c.testPause)
			}
		}
	}

	c.phase(DrainPhaseStopping)
	g.err = stopEnvoy(g, c)
	if !isClosed(g.exited) {
		log.Errorf("envoy exit not confirmed: %v", g.err)
	}
	go func() {
		<-g.exited
		close(g.stopped)
	}()

	stopTelemetry(c)

	r.mu.Lock()
	r.status.Starting = false
	r.mu.Unlock()
}

// drainIdle waits until the drain ends and reports whether it ended because
// Envoy went idle. end is re-read because a later caller may move it earlier.
func drainIdle(g *generation, c shutdownConfig, t0 time.Time, end func() time.Time) bool {
	idle := idleTracker{quiet: c.quiet}
	quiet := c.quiet
	for {
		if !time.Now().Before(end()) {
			log.Infof("drain timeout reached")
			return false
		}
		// Only if we reached the minimum drain time - might still receive new connections.
		if quiet > 0 && time.Since(t0) >= c.minDrainTime {
			ctx, cancel := pollContext(g, end)
			gauges, err := pollDrainGauges(ctx, c.admin)
			cancel()
			if errors.Is(err, errUDPListener) {
				log.Infof("idle exit disabled for this drain: %v", err)
				quiet = 0
			} else if err != nil {
				log.Warnf("idle check: %v", err)
			} else {
				log.Debugf("idle check: %+v", gauges)
			}
			// Q counts from completed samples, never the fetch latency.
			if idle.observe(time.Now(), gauges, err) {
				log.Infof("envoy idle for %s, ending drain", c.quiet)
				return true
			}
		}
		wait := c.timeouts.poll
		if rest := time.Until(end()); rest < wait {
			wait = rest
		}
		t := time.NewTimer(wait)
		select {
		case <-g.exited:
			t.Stop()
			log.Infof("envoy exited while draining")
			return false
		case <-g.tightened:
		case <-t.C:
		}
		t.Stop()
	}
}

// pollContext ends with the drain, following any later move of its end.
func pollContext(g *generation, end func() time.Time) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		t := time.NewTimer(time.Until(end()))
		defer t.Stop()
		for {
			select {
			case <-g.tightened:
				t.Reset(time.Until(end()))
			case <-t.C:
				cancel()
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return ctx, cancel
}

// stopEnvoy waits for the supervisor, never the process: only run() waits on it.
func stopEnvoy(g *generation, c shutdownConfig) error {
	if isClosed(g.exited) {
		return nil
	}
	if c.cmd != nil {
		if err := c.admin.post("quitquitquit"); err != nil {
			log.Errorf("error posting to quitquitquit: %v", err)
		}
	}
	if waitClosed(g.exited, c.timeouts.quitWait) {
		return c.lastExit()
	}
	if c.cmd == nil {
		return errors.New("envoy supervisor did not stop")
	}
	log.Warnf("envoy did not exit within %s, killing it", c.timeouts.quitWait)
	if err := c.kill(c.cmd.Process); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("failed to kill envoy: %w", err)
	}
	if !waitClosed(g.exited, c.timeouts.killWait) {
		return errors.New("envoy did not exit after SIGKILL")
	}
	return errEnvoyKilled
}

// shutdownTelemetry flushes the runtime metrics and stops the otel collector.
func (r *Runtime) shutdownTelemetry(ctx context.Context) error {
	var errs []error
	if m := r.metricsIfStarted(); m != nil {
		if err := m.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("runtime metrics: %w", err))
		}
	}
	if r.tel.otelCollector != nil {
		if err := r.tel.otelCollector.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("otel collector: %w", err))
		}
	}
	return errors.Join(errs...)
}

// stopTelemetry stops the telemetry within its budget.
func stopTelemetry(c shutdownConfig) {
	if c.stopTel == nil {
		return
	}
	// The last push of the metrics needs a live context, never the caller's.
	ctx, cancel := context.WithTimeout(context.Background(), c.timeouts.telemetry)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- c.stopTel(ctx) }()
	select {
	case err := <-errCh:
		if err != nil {
			log.Errorf("error shutting down telemetry: %v", err)
		}
	case <-ctx.Done():
		log.Errorf("telemetry did not stop within %s", c.timeouts.telemetry)
	}
}

// adminClient calls the Envoy admin API with a deadline on every call.
type adminClient struct {
	host     string
	timeouts shutdownTimeouts
}

func (a adminClient) post(path string) error {
	if a.host == "" {
		return errors.New("envoy admin host not set")
	}
	c := &http.Client{Timeout: a.timeouts.admin}
	resp, err := c.Post("http://"+a.host+"/"+path, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	return nil
}

func (a adminClient) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	if a.host == "" {
		return nil, errors.New("envoy admin host not set")
	}
	u := url.URL{Scheme: "http", Host: a.host, Path: "/" + path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Timeout: a.timeouts.stats}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /%s: unexpected response status: %s", path, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
