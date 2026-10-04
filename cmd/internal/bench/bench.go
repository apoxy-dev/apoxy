// SPDX-License-Identifier: AGPL-3.0-only

// Package bench has the RTT probes and the time and CPU helpers of the TCP
// benchmark commands.
package bench

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// userHZ is the clock tick of /proc/stat.
const userHZ = 100

// Sleep waits for d. It returns early when ctx ends or a flow stops.
func Sleep(ctx context.Context, d time.Duration, done <-chan error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err == nil {
			err = errors.New("a flow stopped before the end of the run")
		}
		return err
	case <-time.After(d):
		return nil
	}
}

// CPUSeconds returns the user and system CPU time of this process.
func CPUSeconds() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()).Seconds()
}

// HostCPUSeconds returns the busy CPU time of all CPUs of the host, with the
// kernel work in IRQ and softirq. It returns -1 when it cannot read /proc/stat.
func HostCPUSeconds() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return -1
	}
	return hostBusy(string(b))
}

// hostBusy reads user, nice, system, irq and softirq from the cpu line of
// /proc/stat, in seconds, or -1.
func hostBusy(stat string) float64 {
	line, _, _ := strings.Cut(stat, "\n")
	f := strings.Fields(line)
	if len(f) < 8 || f[0] != "cpu" {
		return -1
	}
	var busy uint64
	for _, i := range []int{1, 2, 3, 6, 7} {
		n, err := strconv.ParseUint(f[i], 10, 64)
		if err != nil {
			return -1
		}
		busy += n
	}
	return float64(busy) / userHZ
}

// CPUTicks are the clock ticks of one CPU in /proc/stat, and its NET_RX and
// NET_TX softirq runs in /proc/softirqs.
type CPUTicks struct {
	User   uint64 `json:"user"` // User and nice.
	System uint64 `json:"system"`
	IRQ    uint64 `json:"irq"`  // IRQ and softirq.
	Idle   uint64 `json:"idle"` // Idle, iowait and steal.
	NetRX  uint64 `json:"net_rx,omitempty"`
	NetTX  uint64 `json:"net_tx,omitempty"`
}

// PerCPU returns the ticks of each CPU of the host, or nil when it cannot
// read /proc/stat.
func PerCPU() []CPUTicks {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	cpus := perCPU(string(b))
	if b, err := os.ReadFile("/proc/softirqs"); err == nil {
		addSoftIRQs(cpus, string(b))
	}
	return cpus
}

// addSoftIRQs adds the NET_RX and NET_TX rows of /proc/softirqs to cpus. The
// columns are the CPUs in order.
func addSoftIRQs(cpus []CPUTicks, softirqs string) {
	for line := range strings.Lines(softirqs) {
		f := strings.Fields(line)
		if len(f) < 2 || (f[0] != "NET_RX:" && f[0] != "NET_TX:") {
			continue
		}
		for i, v := range f[1:min(len(f), len(cpus)+1)] {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				break
			}
			if f[0] == "NET_RX:" {
				cpus[i].NetRX = n
			} else {
				cpus[i].NetTX = n
			}
		}
	}
}

// perCPU reads the "cpuN" lines of /proc/stat, in CPU order. It returns nil
// for a bad line.
func perCPU(stat string) []CPUTicks {
	var out []CPUTicks
	for line := range strings.Lines(stat) {
		f := strings.Fields(line)
		if len(f) == 0 || len(f[0]) < 4 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if len(f) < 9 {
			return nil
		}
		var v [8]uint64
		for i := range v {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return nil
			}
			v[i] = n
		}
		out = append(out, CPUTicks{User: v[0] + v[1], System: v[2], IRQ: v[5] + v[6], Idle: v[3] + v[4] + v[7]})
	}
	return out
}
