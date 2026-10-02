// SPDX-License-Identifier: AGPL-3.0-only

package steer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Listen opens n UDP sockets on addr in one SO_REUSEPORT group with the
// program. Socket i needs ConnIDs{Index: i}, and keeps i while all stay open.
func Listen(network, addr string, n int) ([]*net.UDPConn, error) {
	if n < 1 || n > MaxSockets {
		return nil, fmt.Errorf("steer: %d sockets is not from 1 to %d", n, MaxSockets)
	}
	prog, err := bpf.Assemble(Program(n))
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return control(c, func(fd int) error { return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) })
	}}
	conns := make([]*net.UDPConn, 0, n)
	closeAll := func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}
	// The kernel gives the sockets their group index in bind order.
	for range n {
		pc, err := lc.ListenPacket(context.Background(), network, addr)
		if err != nil {
			closeAll()
			return nil, err
		}
		conns = append(conns, pc.(*net.UDPConn))
		addr = pc.LocalAddr().String()
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, ins := range prog {
		filter[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	fprog := &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	rc, err := conns[0].SyscallConn()
	if err == nil {
		err = control(rc, func(fd int) error {
			return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_CBPF, fprog)
		})
	}
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("steer: attach program: %w", err)
	}
	return conns, nil
}

func control(c syscall.RawConn, f func(fd int) error) error {
	var ferr error
	err := c.Control(func(fd uintptr) { ferr = f(int(fd)) })
	return errors.Join(err, ferr)
}
