// SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"
)

const (
	// blockRate samples about one blocking event for each 1 ms of blocked time.
	blockRate = int(time.Millisecond)
	// mutexFraction samples one of 100 contention events.
	mutexFraction = 100
	// defaultTraceTime is the length of the runtime trace. A trace of a full run is too large.
	defaultTraceTime = 3 * time.Second
)

// Profiles are the pprof files, the runtime trace and the kernel counters of a run. An
// empty path writes no file.
type Profiles struct {
	CPU, Block, Mutex string
	// Trace gets a runtime trace of the first TraceTime of the measured window.
	Trace     string
	TraceTime time.Duration
	// Kernel is the path prefix of the kernel counters of the measured window: the
	// snapshots PREFIX-1.txt, PREFIX-m.txt (the middle) and PREFIX-2.txt, and the
	// kernel stacks of the second half, PREFIX-stacks.txt.
	Kernel string
}

// AddFlags adds -cpuprofile, -blockprofile, -mutexprofile, -trace, -trace-time and -kernel to fs.
func (p *Profiles) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&p.CPU, "cpuprofile", "", "write a CPU profile of the run to this file")
	fs.StringVar(&p.Block, "blockprofile", "", "write a goroutine blocking profile to this file at the end")
	fs.StringVar(&p.Mutex, "mutexprofile", "", "write a mutex contention profile to this file at the end")
	fs.StringVar(&p.Trace, "trace", "", "write a runtime trace of the start of the measured window to this file")
	fs.DurationVar(&p.TraceTime, "trace-time", defaultTraceTime, "length of the runtime trace")
	fs.StringVar(&p.Kernel, "kernel", "", "write the kernel counters and the kernel stacks of the measured window to files with this prefix (Linux, root)")
}

// Running are the started profiles of a process. A nil Running does nothing.
type Running struct {
	p   Profiles
	cpu *os.File

	mu     sync.Mutex
	trace  *os.File // The trace file while the trace runs.
	traced bool     // Set when the trace started.
	kernel *kernel  // The kernel counters, from mark 1.
	marks  [3]bool  // The marks that Mark got.
}

// Start starts the profiles. Call Stop before the process exits: it writes the files.
func (p Profiles) Start() (*Running, error) {
	r := &Running{p: p}
	if p.CPU != "" {
		cpu, err := os.Create(p.CPU)
		if err != nil {
			return nil, err
		}
		if err := pprof.StartCPUProfile(cpu); err != nil {
			_ = cpu.Close()
			return nil, fmt.Errorf("start the CPU profile: %w", err)
		}
		r.cpu = cpu
	}
	if p.Block != "" {
		runtime.SetBlockProfileRate(blockRate)
	}
	if p.Mutex != "" {
		runtime.SetMutexProfileFraction(mutexFraction)
	}
	return r, nil
}

// Mark tells the profiles that the run took mark i. Mark 1 is the start of the
// measured window, which has the length window, and mark 2 is its end. Only the
// first call for a mark does work.
func (r *Running) Mark(i int, window time.Duration) error {
	if r == nil || i < 1 || i >= len(r.marks) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.marks[i] {
		return nil
	}
	r.marks[i] = true
	if i == 2 {
		if r.kernel == nil {
			return nil
		}
		return r.kernel.end()
	}
	var errs []error
	if r.p.Kernel != "" {
		// The stack sampler runs in the second half of the window. Its clock events
		// change how the kernel counts the ticks of an idle CPU.
		k, err := startKernel(r.p.Kernel, window/2)
		r.kernel = k
		errs = append(errs, err)
	}
	return errors.Join(append(errs, r.startTrace())...)
}

// startTrace starts the runtime trace, which stops after TraceTime. The caller holds mu.
func (r *Running) startTrace() error {
	if r.p.Trace == "" || r.traced {
		return nil
	}
	r.traced = true
	f, err := os.Create(r.p.Trace)
	if err != nil {
		return err
	}
	if err := trace.Start(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("start the runtime trace: %w", err)
	}
	r.trace = f
	time.AfterFunc(r.p.TraceTime, func() { _ = r.stopTrace() })
	return nil
}

// stopTrace ends the runtime trace, if it runs, and closes its file.
func (r *Running) stopTrace() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trace == nil {
		return nil
	}
	trace.Stop()
	err := r.trace.Close()
	r.trace = nil
	return err
}

// Stop stops the profiles and writes their files.
func (r *Running) Stop() error {
	if r == nil {
		return nil
	}
	errs := []error{r.stopTrace()}
	r.mu.Lock()
	if r.kernel != nil {
		r.kernel.close()
		r.kernel = nil
	}
	r.mu.Unlock()
	if r.cpu != nil {
		pprof.StopCPUProfile()
		errs = append(errs, r.cpu.Close())
	}
	errs = append(errs, writeProfile("block", r.p.Block), writeProfile("mutex", r.p.Mutex))
	return errors.Join(errs...)
}

func writeProfile(name, path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	err = pprof.Lookup(name).WriteTo(f, 0)
	return errors.Join(err, f.Close())
}
