// SPDX-License-Identifier: AGPL-3.0-only

package udpbatch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// firstSocket is the classic BPF program "return 0". With it, the kernel gives
// each received packet to the first socket of a SO_REUSEPORT group.
var firstSocket = [1]unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K}}

// copied are the options that Sync copies from the read socket, as level and name.
var copied = [...][2]int{
	{unix.SOL_SOCKET, unix.SO_BROADCAST},
	{unix.IPPROTO_IP, unix.IP_MTU_DISCOVER},
	{unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER},
	// The GRO lookup of the kernel can find the send socket, and the kernel joins
	// received packets only for a socket with UDP_GRO.
	{unix.IPPROTO_UDP, unix.UDP_GRO},
}

var errNoSpace = errors.New("udpbatch: message has more packets than the batch")

// SendSocket is a UDP socket that only sends, from the address and port of a
// read socket. The Go poller does not have it, so the kernel has no waiter to
// wake when the NIC frees a sent packet. A full send buffer holds a send.
type SendSocket struct {
	fd   int
	read syscall.RawConn // The read socket.

	// mu is held for read while a call uses fd, and for write to close fd.
	mu     sync.RWMutex
	closed atomic.Bool
}

// Listen opens a UDP socket on laddr as net.ListenUDP does, and a send socket
// on the same address and port. The two are one SO_REUSEPORT group, and the
// first socket gets all received packets.
func Listen(network string, laddr *net.UDPAddr) (*net.UDPConn, *SendSocket, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return control(c, func(fd int) error {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				return err
			}
			// The program makes the group now, before the send socket binds. The
			// kernel gives a socket with a group a port that no other socket has.
			prog := unix.SockFprog{Len: uint16(len(firstSocket)), Filter: &firstSocket[0]}
			return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_CBPF, &prog)
		})
	}}
	addr := ":0"
	if laddr != nil {
		addr = laddr.String()
	}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, nil, err
	}
	uc := pc.(*net.UDPConn)
	s, err := openSend(uc)
	if err != nil {
		_ = uc.Close()
		return nil, nil, fmt.Errorf("udpbatch: open send socket: %w", err)
	}
	return uc, s, nil
}

// openSend opens a socket with the IP family and the address of uc, and adds
// it to the SO_REUSEPORT group of uc.
func openSend(uc *net.UDPConn) (*SendSocket, error) {
	rc, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var sa unix.Sockaddr
	domain, v6only := unix.AF_INET, 0
	if err := control(rc, func(fd int) error {
		var err error
		if sa, err = unix.Getsockname(fd); err != nil {
			return err
		}
		if _, ok := sa.(*unix.SockaddrInet6); ok {
			domain = unix.AF_INET6
			v6only, err = unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		}
		return err
	}); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	s := &SendSocket{fd: fd, read: rc}
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err == nil && domain == unix.AF_INET6 {
		// The kernel joins only sockets with the same IPV6_V6ONLY in one group.
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, v6only)
	}
	if err == nil {
		// The socket reads nothing, so it gets the smallest receive buffer.
		err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 0)
	}
	if err == nil {
		err = os.NewSyscallError("bind", unix.Bind(fd, sa))
	}
	if err == nil {
		err = s.Sync()
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return s, nil
}

// Sync copies the send buffer size and the options in copied from the read
// socket. Call it after they change on the read socket.
func (s *SendSocket) Sync() error {
	var snd int
	var vals [len(copied)]int
	var has [len(copied)]bool
	if err := control(s.read, func(fd int) error {
		var err error
		if snd, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF); err != nil {
			return err
		}
		for i, o := range copied {
			// A socket of one IP family does not have the options of the other.
			vals[i], err = unix.GetsockoptInt(fd, o[0], o[1])
			has[i] = err == nil
		}
		return nil
	}); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	// The kernel reports twice the size that a caller set.
	var err error
	if unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, snd/2) != nil {
		err = unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, snd/2)
	}
	for i, o := range copied {
		if has[i] {
			err = errors.Join(err, unix.SetsockoptInt(s.fd, o[0], o[1], vals[i]))
		}
	}
	return err
}

// Close closes the socket. A send that waits for buffer space returns
// net.ErrClosed.
func (s *SendSocket) Close() error {
	if s.closed.Swap(true) {
		return net.ErrClosed
	}
	// The shutdown wakes a send that waits in the kernel, and the lock waits
	// until no call uses fd.
	_ = unix.Shutdown(s.fd, unix.SHUT_RDWR)
	s.mu.Lock()
	defer s.mu.Unlock()
	return unix.Close(s.fd)
}

// sendmmsg sends hs with one call, and returns the count of messages that the
// kernel took. The call waits in the kernel while the send buffer is full.
func (s *SendSocket) sendmmsg(hs []mmsghdr) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for {
		if s.closed.Load() {
			return 0, net.ErrClosed
		}
		n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(s.fd), uintptr(unsafe.Pointer(&hs[0])), uintptr(len(hs)), unix.MSG_NOSIGNAL, 0, 0)
		switch {
		case errno == 0:
			return int(n), nil
		case errno == unix.EINTR:
		case s.closed.Load():
			// The shutdown of Close ended the call.
			return 0, net.ErrClosed
		default:
			return 0, os.NewSyscallError("sendmmsg", errno)
		}
	}
}

// NewSend returns a batch of at most size packets that sends on s.
func NewSend(s *SendSocket, size int) *Batch {
	w := &sendWriter{
		s:     s,
		hs:    make([]mmsghdr, size),
		iovs:  make([]unix.Iovec, size),
		names: make([]unix.RawSockaddrInet6, size),
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	gso := false
	if !s.closed.Load() {
		_, err := unix.GetsockoptInt(s.fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		gso = err == nil
	}
	return batchOf(w, gso, size)
}

// mmsghdr is struct mmsghdr of sendmmsg(2). x/sys has no type for it.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// sendWriter sends the messages of one batch on a send socket. Its slices have
// space for all messages and packets of the batch, so a send allocates nothing.
type sendWriter struct {
	s     *SendSocket
	hs    []mmsghdr
	iovs  []unix.Iovec
	names []unix.RawSockaddrInet6 // An IPv4 address uses the start of an element.
	// zone and zoneID are the last IPv6 zone and its index.
	zone   string
	zoneID uint32
}

// WriteBatch sends ms with one sendmmsg call. It returns the count of messages
// that the kernel took, and an error only when the kernel took none.
func (w *sendWriter) WriteBatch(ms []ipv4.Message, _ int) (int, error) {
	n, used := 0, 0
	for i := range ms {
		m := &ms[i]
		if n == len(w.hs) || used+len(m.Buffers) > len(w.iovs) {
			break
		}
		h := &w.hs[n]
		*h = mmsghdr{}
		h.Hdr.Name = (*byte)(unsafe.Pointer(&w.names[n]))
		h.Hdr.Namelen = w.name(&w.names[n], m.Addr.(*net.UDPAddr))
		if len(m.Buffers) > 0 {
			h.Hdr.Iov = &w.iovs[used]
			h.Hdr.SetIovlen(len(m.Buffers))
		}
		for _, b := range m.Buffers {
			v := &w.iovs[used]
			if len(b) > 0 {
				v.Base = &b[0]
			}
			v.SetLen(len(b))
			used++
		}
		if len(m.OOB) > 0 {
			h.Hdr.Control = &m.OOB[0]
			h.Hdr.SetControllen(len(m.OOB))
		}
		n++
	}
	if n == 0 {
		if len(ms) == 0 {
			return 0, nil
		}
		return 0, errNoSpace
	}
	sent, err := w.s.sendmmsg(w.hs[:n])
	// The writer keeps no packet after the send.
	clear(w.hs[:n])
	clear(w.iovs[:used])
	return sent, err
}

// name writes a to sa as x/net does, and returns its size. An IPv4 address is
// an AF_INET address, also on an IPv6 socket.
func (w *sendWriter) name(sa *unix.RawSockaddrInet6, a *net.UDPAddr) uint32 {
	if ip4 := a.IP.To4(); ip4 != nil {
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		*sa4 = unix.RawSockaddrInet4{Family: unix.AF_INET, Port: htons(a.Port)}
		copy(sa4.Addr[:], ip4)
		return unix.SizeofSockaddrInet4
	}
	*sa = unix.RawSockaddrInet6{Family: unix.AF_INET6, Port: htons(a.Port), Scope_id: w.zoneIndex(a.Zone)}
	copy(sa.Addr[:], a.IP)
	return unix.SizeofSockaddrInet6
}

// zoneIndex returns the index of an IPv6 zone. It keeps the last zone, so a
// send to one zone allocates nothing.
func (w *sendWriter) zoneIndex(zone string) uint32 {
	if zone == "" {
		return 0
	}
	if zone != w.zone {
		w.zone, w.zoneID = zone, 0
		if ifi, err := net.InterfaceByName(zone); err == nil {
			w.zoneID = uint32(ifi.Index)
		} else if id, err := strconv.ParseUint(zone, 10, 32); err == nil {
			w.zoneID = uint32(id)
		}
	}
	return w.zoneID
}

// htons returns port in the byte order of a socket address.
func htons(port int) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(port))
	return binary.NativeEndian.Uint16(b[:])
}

func control(c syscall.RawConn, f func(fd int) error) error {
	var ferr error
	err := c.Control(func(fd uintptr) { ferr = f(int(fd)) })
	return errors.Join(err, ferr)
}
