// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

var errFloodLinux = errors.New("the flood commands of vpcbench run only on Linux")

// floodSender sends the packets of all source ports.
type floodSender struct {
	dev  string
	segs int
}

func newFloodSender(netip.Addr, func(int) netip.AddrPort, floodRun, int) (*floodSender, error) {
	return nil, errFloodLinux
}

func (s *floodSender) send(context.Context, time.Duration) (floodSent, error) {
	return floodSent{}, errFloodLinux
}

func (s *floodSender) mark(time.Time) *floodMark { return nil }

func (s *floodSender) close() {}

func runFloodRelay(context.Context, floodOptions, func(netip.AddrPort)) error { return errFloodLinux }

func runFloodCounter(context.Context, floodOptions, func(netip.AddrPort)) error {
	return errFloodLinux
}
