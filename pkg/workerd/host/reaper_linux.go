// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package host

import (
	"log/slog"
	"os"
	"os/signal"
	"unsafe"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
	"golang.org/x/sys/unix"
)

// StartChildReaper installs a SIGCHLD-driven reaper for orphan child processes.
//
// workerd-host runs as PID 1 in its container. When `runsc create` spawns the
// Sentry+gofer and exits, those processes are re-parented to PID 1 (us) and
// become zombies when they exit. Without reaping, `runsc wait`'s kill(pid,0)
// liveness probe sees a zombie as alive for the full 2-minute backoff. To avoid
// racing the core's own cmd.Wait(), the reaper consults sandbox.ShouldSkipReap
// and skips PIDs the core is actively waiting on.
func StartChildReaper() {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, unix.SIGCHLD)
	go func() {
		for range ch {
			drainReapable()
		}
	}()
}

// drainReapable reaps every currently-reapable child not owned by a core
// cmd.Wait(). It peeks the next reapable child with WNOWAIT, checks ownership,
// and either skips (the core's Wait will collect it) or reaps with wait4.
func drainReapable() {
	for {
		pid, err := peekReapablePid()
		if err != nil || pid <= 0 {
			return
		}
		if sandbox.ShouldSkipReap(pid) {
			// The core's cmd.Wait() will collect this one; stop the drain.
			// Linux redelivers SIGCHLD when another orphan is reapable.
			return
		}
		var status unix.WaitStatus
		reaped, err := unix.Wait4(pid, &status, unix.WNOHANG, nil)
		if err != nil || reaped <= 0 {
			return
		}
		slog.Info("Reaped orphan child",
			"pid", reaped,
			"exited", status.Exited(),
			"exit_status", status.ExitStatus(),
			"signaled", status.Signaled())
	}
}

// peekReapablePid returns the PID of the next reapable child without consuming
// its zombie status. Raw waitid via Syscall6 because x/sys/unix opaque-bytes the
// si_pid field. Linux's siginfo_t lays si_pid at byte offset 16 (after si_signo
// / si_errno / si_code / _pad), stable across amd64/arm64.
func peekReapablePid() (int, error) {
	var buf [128]byte
	_, _, errno := unix.Syscall6(
		unix.SYS_WAITID,
		uintptr(unix.P_ALL),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unix.WEXITED|unix.WNOHANG|unix.WNOWAIT),
		0, 0,
	)
	if errno != 0 {
		if errno == unix.ECHILD {
			return 0, nil
		}
		return 0, errno
	}
	pid := int32(buf[16]) | int32(buf[17])<<8 | int32(buf[18])<<16 | int32(buf[19])<<24
	return int(pid), nil
}
