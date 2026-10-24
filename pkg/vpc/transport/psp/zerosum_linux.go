// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// acceptZeroSum makes c accept IPv6 UDP packets with checksum 0, as the PSP specification
// requires. Linux accepts them on IPv4, and drops them on IPv6 with no UDP_NO_CHECK6_RX.
func acceptZeroSum(c *net.UDPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_NO_CHECK6_RX, 1)
	})
	return errors.Join(err, serr)
}
