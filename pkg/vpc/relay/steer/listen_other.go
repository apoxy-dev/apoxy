// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package steer

import (
	"errors"
	"net"
)

// Listen opens one UDP socket on addr. More sockets need Linux.
func Listen(network, addr string, n int) ([]*net.UDPConn, error) {
	if n != 1 {
		return nil, errors.New("steer: more than one socket needs Linux")
	}
	ua, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP(network, ua)
	if err != nil {
		return nil, err
	}
	return []*net.UDPConn{c}, nil
}
