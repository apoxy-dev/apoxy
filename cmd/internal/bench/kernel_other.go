// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package bench

import (
	"errors"
	"time"
)

// kernel measures the kernel work of a Linux host.
type kernel struct{}

func startKernel(string, time.Duration) (*kernel, error) {
	return nil, errors.New("the kernel counters need Linux")
}

func (k *kernel) end() error { return nil }

func (k *kernel) close() {}
