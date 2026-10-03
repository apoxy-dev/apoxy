// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// batchWrites reports whether x/net sends a batch with one sendmmsg call.
const batchWrites = true

// gsoSupported reports whether the kernel can send uc packets with UDP_SEGMENT.
func gsoSupported(uc *net.UDPConn) bool {
	rc, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		_, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
	}); err != nil {
		return false
	}
	return serr == nil
}

// appendSegmentSize appends a UDP_SEGMENT control message with size to b.
func appendSegmentSize(b []byte, size uint16) []byte {
	start := len(b)
	b = append(b, make([]byte, unix.CmsgSpace(2))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[start]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&b[start+unix.CmsgSpace(0)])) = size
	return b
}

// isGSOError reports whether the socket or the device refused UDP_SEGMENT.
// A device with no checksum offload gives EIO.
func isGSOError(err error) bool {
	return errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOPROTOOPT)
}
