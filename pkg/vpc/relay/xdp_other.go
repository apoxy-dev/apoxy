// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package relay

import "errors"

// XDP forwards the PSP packets of the rows of a router in XDP. It needs Linux.
type XDP struct{}

// StartXDP returns an error: XDP needs Linux.
func (r *Router) StartXDP(XDPConfig) (*XDP, string, error) {
	return nil, "", errors.New("XDP needs Linux")
}

// Close does nothing.
func (x *XDP) Close() error { return nil }
