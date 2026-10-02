// SPDX-License-Identifier: AGPL-3.0-only

// Package bench has the RTT probes and the time and CPU helpers of the TCP
// benchmark commands.
package bench

import (
	"context"
	"errors"
	"syscall"
	"time"
)

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
