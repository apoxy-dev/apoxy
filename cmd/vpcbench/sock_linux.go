// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sockRcvbuf returns the receive buffer of the socket of c as the kernel reports it,
// which is twice the size that was set, or -1.
func sockRcvbuf(c syscall.Conn) int64 {
	v := int64(-1)
	control(c, func(fd int) {
		if n, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
			v = int64(n)
		}
	})
	return v
}

// sockDrops returns the packets that the socket of c dropped, most because its
// receive buffer was full, or -1.
func sockDrops(c syscall.Conn) int64 {
	v := int64(-1)
	control(c, func(fd int) {
		var mi [unix.SK_MEMINFO_VARS]uint32
		n := uint32(unsafe.Sizeof(mi))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_MEMINFO,
			uintptr(unsafe.Pointer(&mi[0])), uintptr(unsafe.Pointer(&n)), 0)
		if errno == 0 && n > unix.SK_MEMINFO_DROPS*4 {
			v = int64(mi[unix.SK_MEMINFO_DROPS])
		}
	})
	return v
}

// control runs f with the file descriptor of c.
func control(c syscall.Conn, f func(fd int)) {
	if rc, err := c.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) { f(int(fd)) })
	}
}
