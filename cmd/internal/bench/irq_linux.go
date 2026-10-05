// SPDX-License-Identifier: AGPL-3.0-only

package bench

import "slices"

// netRX is the kind of the NET_RX softirq. It runs the NAPI polls of the
// drivers, and with them the XDP programs.
var netRX = slices.Index(softirqs[:], "NET_RX")

// IRQTimer measures the run time of the IRQ and softirq handlers of each CPU
// with BPF programs. The softirq fields of /proc/stat can read much too low.
type IRQTimer struct{ t *irqTimer }

// NewIRQTimer starts the timer. The process needs the right to load BPF programs.
func NewIRQTimer() (*IRQTimer, error) {
	t, err := newIRQTimer()
	if err != nil {
		return nil, err
	}
	return &IRQTimer{t}, nil
}

// Nanos returns the time in ns that each CPU ran IRQ and softirq handlers since
// the start, and the part of the NET_RX softirq. A nil timer returns nothing.
func (t *IRQTimer) Nanos() (all, rx []uint64, err error) {
	if t == nil {
		return nil, nil, nil
	}
	kinds, err := t.t.read()
	if err != nil {
		return nil, nil, err
	}
	all, rx = make([]uint64, len(kinds[netRX])), make([]uint64, len(kinds[netRX]))
	for k, cpus := range kinds {
		for cpu, v := range cpus {
			all[cpu] += v.NS
			if k == netRX {
				rx[cpu] = v.NS
			}
		}
	}
	return all, rx, nil
}

// Close stops the timer.
func (t *IRQTimer) Close() {
	if t != nil {
		t.t.close()
	}
}
