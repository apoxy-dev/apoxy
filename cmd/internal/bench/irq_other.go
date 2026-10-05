// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package bench

import "errors"

// IRQTimer measures the run time of the IRQ and softirq handlers of a Linux host.
type IRQTimer struct{}

func NewIRQTimer() (*IRQTimer, error) { return nil, errors.New("the IRQ timer needs Linux") }

func (t *IRQTimer) Nanos() (all, rx []uint64, err error) { return nil, nil, nil }

func (t *IRQTimer) Close() {}
