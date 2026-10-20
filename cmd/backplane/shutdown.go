package main

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/pkg/backplane/envoy"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

var (
	drainPhaseGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "backplane_drain_phase",
		Help: "Shutdown phase: 0 serving, 1 draining, 2 idle, 3 stopping, 4 leaving.",
	})
	drainPhaseTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "backplane_drain_phase_timestamp_seconds",
		Help: "Unix time at which each shutdown phase began.",
	}, []string{"phase"})
)

func init() {
	crmetrics.Registry.MustRegister(drainPhaseGauge, drainPhaseTimestamp)
}

func setDrainPhase(p envoy.DrainPhase) {
	drainPhaseGauge.Set(float64(p))
	drainPhaseTimestamp.WithLabelValues(strconv.Itoa(int(p))).SetToCurrentTime()
}

// Reserve time to stop Envoy and leave before kubelet's SIGKILL.
type shutdownBudget struct {
	margin time.Duration
	stop   time.Duration
	leave  time.Duration
	slack  time.Duration
}

var defaultShutdownBudget = shutdownBudget{
	margin: 2 * time.Second,
	stop:   4 * time.Second,
	leave:  8 * time.Second,
	slack:  time.Second,
}

// shutdownDeps is everything shutdownSequence acts on.
type shutdownDeps struct {
	// grace is the pod's termination grace period. Zero means drain timeout
	// plus 5s, the chart's value before --shutdown_grace_period.
	grace        time.Duration
	budget       shutdownBudget
	leaveEnabled bool

	drainTimeout func() time.Duration
	// stopped closes only once Envoy's exit is confirmed.
	shutdown  func(drainEnd time.Time) (stopped, done <-chan struct{})
	killEnvoy func() error
	leave     func() <-chan struct{}
	leaveErr  func() error
	phase     func(envoy.DrainPhase)
	exit      func(code int)
}

// Preserve time to leave olric before kubelet kills the pod.
func shutdownSequence(d shutdownDeps) {
	t0 := time.Now()
	grace := d.grace
	if grace <= 0 {
		grace = d.drainTimeout() + 5*time.Second
	}
	hard := t0.Add(grace - d.budget.margin)
	drainEnd := hard.Add(-(d.budget.stop + d.budget.leave + d.budget.slack))
	log.Infof("shutdown: hard deadline in %s, drain ends in at most %s",
		hard.Sub(t0), drainEnd.Sub(t0))

	var exitOnce sync.Once
	exit := func(code int) { exitOnce.Do(func() { d.exit(code) }) }
	leave := func() <-chan struct{} {
		if !d.leaveEnabled {
			return closedCh
		}
		return d.leave()
	}

	fired := make(chan struct{})
	watchdog := time.AfterFunc(hard.Sub(t0), func() {
		close(fired)
		log.Errorf("shutdown watchdog fired")
		if err := d.killEnvoy(); err != nil {
			log.Errorf("failed to kill envoy: %v", err)
		}
		waitUntil(leave(), hard)
		exit(1)
	})
	defer watchdog.Stop()

	// Leaves even if the Envoy stop overran, so survivors never wait on gossip.
	leaveTimer := time.AfterFunc(hard.Sub(t0)-d.budget.leave, func() {
		if d.leaveEnabled {
			log.Warnf("shutdown: leaving before envoy stopped")
			d.leave()
		}
	})
	defer leaveTimer.Stop()

	stopped, done := d.shutdown(drainEnd)
	select {
	case <-stopped:
	case <-fired:
		return
	}

	leaveTimer.Stop()
	leaveCh := leave()
	if d.leaveEnabled {
		d.phase(envoy.DrainPhaseLeaving)
	}
	doneOK := waitUntil(done, hard)
	leftOK := waitUntil(leaveCh, hard)
	if d.leaveEnabled && leftOK {
		if err := d.leaveErr(); err != nil {
			log.Errorf("shutdown: olric leave failed: %v", err)
		} else {
			log.Infof("shutdown: left the olric cluster")
		}
	}
	if !doneOK || !leftOK {
		// Past the deadline the watchdog owns the exit.
		<-fired
		return
	}
	exit(0)
}

var closedCh = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// waitUntil reports whether ch closed before deadline.
func waitUntil(ch <-chan struct{}, deadline time.Time) bool {
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
}
