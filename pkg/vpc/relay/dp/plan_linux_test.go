// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// noCPU is a CPU that no thread can have: unix.CPUSet has no bit for it, so a pin to it sets an
// empty CPU set, which Linux refuses.
const noCPU = maxCPUs

// processCPUs returns the CPU set of the test process.
func processCPUs(t *testing.T) []int {
	t.Helper()
	var set unix.CPUSet
	require.NoError(t, unix.SchedGetaffinity(0, &set))
	var cpus []int
	for c := range maxCPUs {
		if set.IsSet(c) {
			cpus = append(cpus, c)
		}
	}
	require.NotEmpty(t, cpus)
	return cpus
}

func TestRelayCPUs(t *testing.T) {
	all := processCPUs(t)
	cases := []struct {
		name     string
		cpus     []int
		want     []int
		mismatch bool
	}{
		{name: "no relay.cpus: the CPU set of the process", want: all},
		{name: "a CPU of the process", cpus: all[len(all)-1:], want: all[len(all)-1:]},
		{name: "a CPU that the process does not have", cpus: []int{all[len(all)-1] + 1}, mismatch: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := relayCPUs(tc.cpus)
			if tc.mismatch {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestPinThread pins a locked thread to a CPU. The thread ends with its goroutine, so no other
// goroutine runs on it.
func TestPinThread(t *testing.T) {
	all := processCPUs(t)
	cases := []struct {
		name string
		cpu  int
		err  error
	}{
		{name: "a CPU of the process", cpu: all[len(all)-1]},
		{name: "a CPU that no thread can have", cpu: noCPU, err: unix.EINVAL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			type result struct {
				err  error
				cpus []int
			}
			got := make(chan result, 1)
			go func() {
				runtime.LockOSThread() // No unlock: the pinned thread ends with the goroutine.
				err := pinThread("test", tc.cpu)
				var set unix.CPUSet
				if err := unix.SchedGetaffinity(0, &set); err != nil {
					got <- result{err: err}
					return
				}
				var cpus []int
				for c := range maxCPUs {
					if set.IsSet(c) {
						cpus = append(cpus, c)
					}
				}
				got <- result{err, cpus}
			}()
			r := <-got
			if tc.err != nil {
				assert.ErrorIs(t, r.err, tc.err)
				return
			}
			require.NoError(t, r.err)
			assert.Equal(t, []int{tc.cpu}, r.cpus)
		})
	}
}

// TestRunPinFails gives one thread of the plan a CPU that no thread can have. Run stops with the
// error and puts back the interrupt affinities.
func TestRunPinFails(t *testing.T) {
	const bad = noCPU
	cases := []struct {
		name string
		set  func(d *Device)
	}{
		{name: "an RX goroutine", set: func(d *Device) { d.plan.rx = []int{bad} }},
		{name: "a worker", set: func(d *Device) { d.workers[0].cpu = bad }},
		{name: "a kicker", set: func(d *Device) { d.tx[0].cpu = bad }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine(t, 1, 1, 64)
			e.stop = func() error { return nil } // Run closes the netstack.
			tc.set(e.Device)
			restored := false
			e.restore = func() { restored = true }
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := e.Run(ctx)
			require.Error(t, err)
			assert.ErrorIs(t, err, unix.EINVAL)
			assert.NoError(t, ctx.Err(), "Run stopped before the timeout")
			assert.True(t, restored, "Run put back the interrupt affinities")
		})
	}
}
