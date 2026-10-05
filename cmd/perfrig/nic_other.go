//go:build !linux

package main

import (
	"context"
	"errors"
	"time"
)

// xdpFeatures needs Linux.
func xdpFeatures(string) ([]string, uint32) { return nil, 0 }

// prepareXDP needs Linux.
func prepareXDP(context.Context, string, string, time.Duration) (func(), error) {
	return nil, errors.New("XDP needs Linux")
}
