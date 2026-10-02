// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// setSockBufs sets the send and receive buffers of c to n bytes. With
// CAP_NET_ADMIN it goes above net.core.rmem_max and wmem_max.
func setSockBufs(c *net.UDPConn, n int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		for _, o := range [][2]int{{unix.SO_RCVBUFFORCE, unix.SO_RCVBUF}, {unix.SO_SNDBUFFORCE, unix.SO_SNDBUF}} {
			if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, o[0], n) != nil {
				serr = errors.Join(serr, unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, o[1], n))
			}
		}
	})
	return errors.Join(err, serr)
}
