// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package psp

import (
	"errors"
	"net"
)

// setSockBufs sets the send and receive buffers of c to n bytes.
func setSockBufs(c *net.UDPConn, n int) error {
	return errors.Join(c.SetReadBuffer(n), c.SetWriteBuffer(n))
}
