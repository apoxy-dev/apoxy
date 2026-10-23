// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package dp

import "errors"

// OpenDevice needs AF_XDP, which only Linux has.
func OpenDevice(Interface) (*Device, error) {
	return nil, errors.New("the relay interface needs Linux")
}

// nameThread needs Linux.
func nameThread(string) {}
