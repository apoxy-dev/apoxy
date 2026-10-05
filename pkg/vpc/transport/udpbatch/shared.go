// SPDX-License-Identifier: AGPL-3.0-only

package udpbatch

import (
	"net"
	"syscall"
)

// sharedConn is a UDP socket whose raw writes do not take the write lock of the
// socket.
type sharedConn struct{ *net.UDPConn }

// SyscallConn implements syscall.Conn. Each Batch has its own RawConn.
func (c sharedConn) SyscallConn() (syscall.RawConn, error) {
	rc, err := c.UDPConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return newSharedRaw(rc), nil
}

// sharedRaw is a RawConn whose Write does not wait for other writes on the
// socket. One goroutine at a time can use it.
type sharedRaw struct {
	syscall.RawConn
	f    func(fd uintptr) bool // The write of this call.
	done bool                  // The result of f.
	try  func(fd uintptr)      // Calls f. It is a field, so Write allocates nothing.
}

func newSharedRaw(rc syscall.RawConn) *sharedRaw {
	r := &sharedRaw{RawConn: rc}
	r.try = func(fd uintptr) { r.done = r.f(fd) }
	return r
}

// Write calls f in Control, which keeps the socket open and takes no write lock.
// When the socket cannot take the data now, the usual Write waits for the socket.
func (r *sharedRaw) Write(f func(fd uintptr) bool) error {
	r.f, r.done = f, false
	err := r.RawConn.Control(r.try)
	r.f = nil
	if err != nil || r.done {
		return err
	}
	return r.RawConn.Write(f)
}
