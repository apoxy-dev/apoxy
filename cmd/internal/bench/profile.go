// SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

const (
	// blockRate samples about one blocking event for each 1 ms of blocked time.
	blockRate = int(time.Millisecond)
	// mutexFraction samples one of 100 contention events.
	mutexFraction = 100
)

// Profiles are the pprof files of a run. An empty path writes no file.
type Profiles struct {
	CPU, Block, Mutex string
}

// AddFlags adds -cpuprofile, -blockprofile and -mutexprofile to fs.
func (p *Profiles) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&p.CPU, "cpuprofile", "", "write a CPU profile of the run to this file")
	fs.StringVar(&p.Block, "blockprofile", "", "write a goroutine blocking profile to this file at the end")
	fs.StringVar(&p.Mutex, "mutexprofile", "", "write a mutex contention profile to this file at the end")
}

// Start starts the profiles. Call stop before the process exits: it writes the files.
func (p Profiles) Start() (stop func() error, err error) {
	var cpu *os.File
	if p.CPU != "" {
		if cpu, err = os.Create(p.CPU); err != nil {
			return nil, err
		}
		if err := pprof.StartCPUProfile(cpu); err != nil {
			_ = cpu.Close()
			return nil, fmt.Errorf("start the CPU profile: %w", err)
		}
	}
	if p.Block != "" {
		runtime.SetBlockProfileRate(blockRate)
	}
	if p.Mutex != "" {
		runtime.SetMutexProfileFraction(mutexFraction)
	}
	return func() error {
		var errs []error
		if cpu != nil {
			pprof.StopCPUProfile()
			errs = append(errs, cpu.Close())
		}
		errs = append(errs, writeProfile("block", p.Block), writeProfile("mutex", p.Mutex))
		return errors.Join(errs...)
	}, nil
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
