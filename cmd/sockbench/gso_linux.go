//go:build linux

package main

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
)

// maxGSOSegments is the kernel limit on segments in one GSO send.
const maxGSOSegments = 64

// gsoControl returns a UDP_SEGMENT control message for segments of size bytes.
func gsoControl(size int) ([]byte, error) {
	b := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(b[unix.CmsgLen(0):], uint16(size))
	return b, nil
}
