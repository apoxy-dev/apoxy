// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"errors"
	"syscall"
)

func sockRcvbuf(syscall.Conn) int64 { return -1 }

func sockDrops(syscall.Conn) int64 { return -1 }

func xdpSeconds(string) (func() float64, func(), error) {
	return nil, nil, errors.New("XDP needs Linux")
}
