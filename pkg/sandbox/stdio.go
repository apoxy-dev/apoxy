package sandbox

import (
	"fmt"
	"io"
	"os"
)

// StdioSink is the per-sandbox log destination an embedder attaches to a
// sandbox's stdout/stderr at Start. The core drains the Sentry's stdio
// into Stdout/Stderr (in addition to the caller-facing pipes in stdio
// mode) and calls Close once the sandbox has exited (Wait) or is torn
// down (Delete) so the embedder can flush + release its writers.
//
// clrk's wrapper returns a sink that fans each line into the worker's
// OTLP logs logger + an identity-tagged slog + a per-agent log file; a
// standalone core consumer can leave [Manager]'s sink hook unset, in
// which case the log copy is discarded and only the caller-facing pipes
// receive the stdio.
type StdioSink struct {
	// Stdout/Stderr receive the sandbox's stdout/stderr byte stream. nil
	// is treated as io.Discard.
	Stdout io.Writer
	Stderr io.Writer
	// Close flushes + releases the sink. Called exactly once per sink,
	// after the sandbox exits or is deleted. nil is a no-op.
	Close func()
}

// wireSandboxStdio allocates pipes for the Sentry's stdio. Two pipes per
// stream in stdio mode: an inner pipe (Sentry writes → drain goroutine
// reads) and an outer pipe (drain goroutine writes → caller reads).
// Non-stdio sandboxes skip the outer pipe; stdio still flows into the
// log sink in either mode.
func wireSandboxStdio(sb *Instance, stdio bool) error {
	var toClose []*os.File
	cleanup := func() {
		for _, f := range toClose {
			_ = f.Close()
		}
	}
	pipe := func() (r, w *os.File, err error) {
		r, w, err = os.Pipe()
		if err == nil {
			toClose = append(toClose, r, w)
		}
		return
	}

	outChildR, outChildW, err := pipe()
	if err != nil {
		return fmt.Errorf("creating stdout child pipe: %w", err)
	}
	sb.stdoutChild = outChildW
	sb.stdoutInternalR = outChildR

	errChildR, errChildW, err := pipe()
	if err != nil {
		cleanup()
		return fmt.Errorf("creating stderr child pipe: %w", err)
	}
	sb.stderrChild = errChildW
	sb.stderrInternalR = errChildR

	if !stdio {
		return nil
	}

	inR, inW, err := pipe()
	if err != nil {
		cleanup()
		return fmt.Errorf("creating stdin pipe: %w", err)
	}
	sb.Stdin = inW
	sb.stdinChild = inR

	outerOutR, outerOutW, err := pipe()
	if err != nil {
		cleanup()
		return fmt.Errorf("creating outer stdout pipe: %w", err)
	}
	sb.Stdout = outerOutR
	sb.stdoutToCaller = outerOutW

	outerErrR, outerErrW, err := pipe()
	if err != nil {
		cleanup()
		return fmt.Errorf("creating outer stderr pipe: %w", err)
	}
	sb.Stderr = outerErrR
	sb.stderrToCaller = outerErrW

	return nil
}

// closeStdio tears down every stdio FD on the instance. Idempotent: each
// FD is nil'd after close so a second call (Create cleanup, then Wait,
// then Delete) is harmless.
func (sb *Instance) closeStdio() {
	if sb == nil {
		return
	}
	fds := []**os.File{
		&sb.stdinChild,
		&sb.stdoutChild,
		&sb.stderrChild,
		&sb.stdoutInternalR,
		&sb.stderrInternalR,
		&sb.stdoutToCaller,
		&sb.stderrToCaller,
	}
	for _, f := range fds {
		if *f != nil {
			_ = (*f).Close()
			*f = nil
		}
	}
	if sb.Stdin != nil {
		_ = sb.Stdin.Close()
		sb.Stdin = nil
	}
	if sb.Stdout != nil {
		_ = sb.Stdout.Close()
		sb.Stdout = nil
	}
	if sb.Stderr != nil {
		_ = sb.Stderr.Close()
		sb.Stderr = nil
	}
}

// drainSentryStdio fans the Sentry's stdio writes into the log sink and
// (in stdio mode) the caller-facing outer pipe. callerSink is nil for
// non-stdio sandboxes; closing it on EOF makes the caller's sb.Stdout
// reader return cleanly. logSink nil is treated as io.Discard.
func drainSentryStdio(src io.Reader, callerSink io.WriteCloser, logSink io.Writer) {
	if logSink == nil {
		logSink = io.Discard
	}
	w := logSink
	if callerSink != nil {
		w = io.MultiWriter(callerSink, logSink)
	}
	_, _ = io.Copy(w, src)
	if callerSink != nil {
		_ = callerSink.Close()
	}
}
