// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package psp

import (
	"errors"
	"net"
)

// setSockBufs sets the receive buffer of c to rcv bytes and the send buffer to
// snd bytes.
func setSockBufs(c *net.UDPConn, rcv, snd int) error {
	return errors.Join(c.SetReadBuffer(rcv), c.SetWriteBuffer(snd))
}
