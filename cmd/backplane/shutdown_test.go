package main

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/backplane/envoy"
)

// testBudget scales the production budget down 10x: with a 1.5s grace, H is
// at 1.4s, the drain ends by 0.75s and the leave timer fires at 1.0s.
var testBudget = shutdownBudget{
	margin: 100 * time.Millisecond,
	stop:   200 * time.Millisecond,
	leave:  400 * time.Millisecond,
	slack:  50 * time.Millisecond,
}

const testGrace = 1500 * time.Millisecond

type fakeBackplane struct {
	t0       time.Time
	stopped  chan struct{}
	done     chan struct{}
	leaveCh  chan struct{}
	release  chan struct{}
	exitCode chan int

	mu         sync.Mutex
	events     []string
	at         map[string]time.Duration
	drainEnd   time.Time
	leaveCalls int // db.Shutdown calls
	leaveOnce  sync.Once
	kills      int
	phases     []envoy.DrainPhase
}

func newFakeBackplane() *fakeBackplane {
	return &fakeBackplane{
		t0:       time.Now(),
		stopped:  make(chan struct{}),
		done:     make(chan struct{}),
		leaveCh:  make(chan struct{}),
		release:  make(chan struct{}),
		exitCode: make(chan int, 2),
		at:       map[string]time.Duration{},
	}
}

func (f *fakeBackplane) record(ev string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	if _, ok := f.at[ev]; !ok {
		f.at[ev] = time.Since(f.t0)
	}
}

// after closes ch d after t0.
func (f *fakeBackplane) after(d time.Duration, ev string, ch chan struct{}) {
	time.AfterFunc(time.Until(f.t0.Add(d)), func() {
		f.record(ev)
		close(ch)
	})
}

func (f *fakeBackplane) deps(leave bool) shutdownDeps {
	return shutdownDeps{
		grace:        testGrace,
		budget:       testBudget,
		leaveEnabled: leave,
		drainTimeout: func() time.Duration { return time.Hour },
		shutdown: func(drainEnd time.Time) (<-chan struct{}, <-chan struct{}) {
			f.mu.Lock()
			f.drainEnd = drainEnd
			f.mu.Unlock()
			return f.stopped, f.done
		},
		killEnvoy: func() error {
			f.mu.Lock()
			f.kills++
			f.mu.Unlock()
			return nil
		},
		// Mirrors kvstore.Store.Leave: one db.Shutdown, one shared channel.
		leave: func() <-chan struct{} {
			f.leaveOnce.Do(func() {
				f.mu.Lock()
				f.leaveCalls++
				f.mu.Unlock()
				f.record("leave")
				go func() {
					<-f.release
					f.record("left")
					close(f.leaveCh)
				}()
			})
			return f.leaveCh
		},
		leaveErr: func() error { return nil },
		phase: func(p envoy.DrainPhase) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.phases = append(f.phases, p)
		},
		exit: func(code int) {
			f.record("exit")
			f.exitCode <- code
		},
	}
}

func (f *fakeBackplane) run(t *testing.T, leave bool) (int, time.Duration) {
	t.Helper()
	go shutdownSequence(f.deps(leave))
	select {
	case code := <-f.exitCode:
		f.mu.Lock()
		defer f.mu.Unlock()
		return code, f.at["exit"]
	case <-time.After(5 * time.Second):
		t.Fatal("no exit")
		return 0, 0
	}
}

func (f *fakeBackplane) eventTime(ev string) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.at[ev]
	return d, ok
}

const hardAt = testGrace - 100*time.Millisecond

func TestShutdownLeavesAfterEnvoyStops(t *testing.T) {
	f := newFakeBackplane()
	f.after(100*time.Millisecond, "stopped", f.stopped)
	f.after(150*time.Millisecond, "done", f.done)
	close(f.release)

	code, exitAt := f.run(t, true)
	assert.Equal(t, 0, code)
	assert.Less(t, exitAt, hardAt)

	stoppedAt, _ := f.eventTime("stopped")
	leaveAt, ok := f.eventTime("leave")
	require.True(t, ok)
	assert.GreaterOrEqual(t, leaveAt, stoppedAt)
	doneAt, _ := f.eventTime("done")
	assert.GreaterOrEqual(t, exitAt, doneAt)

	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, 1, f.leaveCalls)
	assert.Zero(t, f.kills)
	assert.Equal(t, []envoy.DrainPhase{envoy.DrainPhaseLeaving}, f.phases)
	assert.WithinDuration(t, f.t0.Add(hardAt-650*time.Millisecond), f.drainEnd, 20*time.Millisecond)
}

func TestShutdownLeaveTimerFiresFirst(t *testing.T) {
	t.Run("leave blocked", func(t *testing.T) {
		f := newFakeBackplane()
		f.after(1200*time.Millisecond, "stopped", f.stopped)
		f.after(1250*time.Millisecond, "done", f.done)
		defer close(f.release)

		code, exitAt := f.run(t, true)
		assert.Equal(t, 1, code, "past the deadline the watchdog exits")
		assert.GreaterOrEqual(t, exitAt, hardAt, "no exit before the deadline")

		leaveAt, _ := f.eventTime("leave")
		stoppedAt, _ := f.eventTime("stopped")
		assert.InDelta(t, float64(hardAt-testBudget.leave), float64(leaveAt), float64(50*time.Millisecond))
		assert.Less(t, leaveAt, stoppedAt)
		f.mu.Lock()
		defer f.mu.Unlock()
		assert.Equal(t, 1, f.leaveCalls, "one db.Shutdown")
	})

	t.Run("leave finishes", func(t *testing.T) {
		f := newFakeBackplane()
		f.after(1100*time.Millisecond, "stopped", f.stopped)
		f.after(1150*time.Millisecond, "done", f.done)
		f.after(1250*time.Millisecond, "released", f.release)

		code, exitAt := f.run(t, true)
		assert.Equal(t, 0, code)
		leftAt, _ := f.eventTime("left")
		assert.GreaterOrEqual(t, exitAt, leftAt, "no exit before the leave")
		assert.Less(t, exitAt, hardAt)
		f.mu.Lock()
		defer f.mu.Unlock()
		assert.Equal(t, 1, f.leaveCalls)
	})
}

func TestShutdownWatchdogExits1(t *testing.T) {
	f := newFakeBackplane()
	close(f.release)

	code, exitAt := f.run(t, true)
	assert.Equal(t, 1, code)
	assert.InDelta(t, float64(hardAt), float64(exitAt), float64(50*time.Millisecond))

	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, 1, f.kills)
	assert.Equal(t, 1, f.leaveCalls)
}

func TestShutdownLeaveDisabled(t *testing.T) {
	f := newFakeBackplane()
	f.after(100*time.Millisecond, "stopped", f.stopped)
	f.after(150*time.Millisecond, "done", f.done)

	code, exitAt := f.run(t, false)
	assert.Equal(t, 0, code)
	assert.Less(t, exitAt, 500*time.Millisecond)

	// The leave timer would have fired by now.
	time.Sleep(hardAt - exitAt)
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Zero(t, f.leaveCalls)
	assert.Empty(t, f.phases)
}

func TestShutdownDefaultGrace(t *testing.T) {
	f := newFakeBackplane()
	close(f.stopped)
	close(f.done)
	close(f.release)
	d := f.deps(true)
	d.grace = 0
	d.drainTimeout = func() time.Duration { return 10 * time.Second }
	go shutdownSequence(d)
	require.Equal(t, 0, <-f.exitCode)

	f.mu.Lock()
	defer f.mu.Unlock()
	// grace = 10s + 5s, H = grace - 100ms, drain end = H - 650ms.
	assert.WithinDuration(t, f.t0.Add(15*time.Second-750*time.Millisecond), f.drainEnd, 20*time.Millisecond)
}

func TestShutdownStopFailedExits1(t *testing.T) {
	f := newFakeBackplane()
	// The shutdown finished, but Envoy's exit was never confirmed.
	f.after(100*time.Millisecond, "done", f.done)
	close(f.release)

	code, exitAt := f.run(t, true)
	assert.Equal(t, 1, code, "never exit 0 while envoy may run")
	assert.GreaterOrEqual(t, exitAt, hardAt)

	leaveAt, _ := f.eventTime("leave")
	assert.InDelta(t, float64(hardAt-testBudget.leave), float64(leaveAt), float64(50*time.Millisecond))
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, 1, f.kills)
	assert.Equal(t, 1, f.leaveCalls)
	assert.Empty(t, f.phases)
}
