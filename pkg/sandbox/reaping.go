//go:build linux

package sandbox

import (
	"os/exec"
	"sync"
)

// reapExclusions tracks PIDs that the host is actively waiting on via
// os/exec.Cmd.Wait(). The host binary's SIGCHLD reaper consults this set
// (via ShouldSkipReap) to avoid racing waitid() against cmd.Wait()
// and returning ECHILD ("waitid: no child processes") to the caller.
//
// Direct subprocesses (runsc create/start/kill/wait/delete) register
// here; indirect descendants (the Sentry and gofer — re-parented to
// the host when their runsc create parent exits) never get registered,
// so the reaper still collects them.
var reapExclusions sync.Map // pid (int) -> struct{}

// ShouldSkipReap reports whether the reaper should skip the given PID
// because cmd.Wait() will collect it. Exported so the host binary's
// SIGCHLD reaper can import it.
func ShouldSkipReap(pid int) bool {
	_, owned := reapExclusions.Load(pid)
	return owned
}

// runCmdReapAware is exec.Cmd.Run() with reaper exclusion bookkeeping
// around the cmd.Wait() call.
func runCmdReapAware(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	reapExclusions.Store(pid, struct{}{})
	defer reapExclusions.Delete(pid)
	return cmd.Wait()
}

// outputCmdReapAware is exec.Cmd.Output() with reaper exclusion
// bookkeeping. Replicates exec.Cmd.Output's stdout-buffering logic
// since exec doesn't expose Output(cmd) as a hook point.
func outputCmdReapAware(cmd *exec.Cmd) ([]byte, error) {
	if cmd.Stdout != nil {
		// Match exec.Cmd.Output's invariant.
		return nil, &exec.Error{Name: cmd.Path, Err: errStdoutSet}
	}
	var stdout stdoutBuffer
	cmd.Stdout = &stdout
	captureErr := cmd.Stderr == nil
	var stderr stdoutBuffer
	if captureErr {
		cmd.Stderr = &stderr
	}
	err := runCmdReapAware(cmd)
	if err != nil && captureErr {
		// Mirror exec.Cmd.Output: attach stderr to the *ExitError.
		if ee, ok := err.(*exec.ExitError); ok {
			ee.Stderr = stderr.Bytes()
		}
	}
	return stdout.Bytes(), err
}

// stdoutBuffer is the minimal write-collector exec.Cmd.Output uses.
// Defined locally rather than imported from elsewhere to keep this
// file self-contained.
type stdoutBuffer struct{ buf []byte }

func (b *stdoutBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}
func (b *stdoutBuffer) Bytes() []byte { return b.buf }

// errStdoutSet matches exec.Cmd.Output's error when Stdout is already
// set by the caller. Spelled by hand since the exec package doesn't
// export its sentinel.
var errStdoutSet = errStringer("exec: Stdout already set")

type errStringer string

func (e errStringer) Error() string { return string(e) }
