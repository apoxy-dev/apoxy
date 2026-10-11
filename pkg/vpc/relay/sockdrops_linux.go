// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The kernel gives the SO_MEMINFO values in this order. The last one counts the
// packets that the socket dropped, for example with a full receive buffer.
const (
	skMeminfoDrops = 8
	skMeminfoVars  = 9
)

// socketDrops returns the packets that the kernel dropped at the socket of c.
// It reports false for a connection with no socket.
func socketDrops(c net.PacketConn) (uint64, bool) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var mem [skMeminfoVars]uint32
	var errno syscall.Errno
	err = rc.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(mem))
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_SOCKET, unix.SO_MEMINFO,
			uintptr(unsafe.Pointer(&mem)), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil || errno != 0 {
		return 0, false
	}
	return uint64(mem[skMeminfoDrops]), true
}
