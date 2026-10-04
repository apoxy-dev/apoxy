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
