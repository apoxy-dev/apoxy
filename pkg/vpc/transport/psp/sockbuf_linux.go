// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// setSockBufs sets the receive buffer of c to rcv bytes and the send buffer to
// snd bytes. With CAP_NET_ADMIN it goes above net.core.rmem_max and wmem_max.
func setSockBufs(c *net.UDPConn, rcv, snd int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		for _, o := range [][3]int{{unix.SO_RCVBUFFORCE, unix.SO_RCVBUF, rcv}, {unix.SO_SNDBUFFORCE, unix.SO_SNDBUF, snd}} {
			if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, o[0], o[2]) != nil {
				serr = errors.Join(serr, unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, o[1], o[2]))
			}
		}
	})
	return errors.Join(err, serr)
}
