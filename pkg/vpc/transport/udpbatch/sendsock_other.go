// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package udpbatch

import "net"

// SendSocket is a UDP socket that only sends. It needs Linux.
type SendSocket struct{}

// Listen opens a UDP socket on laddr as net.ListenUDP does. It returns no send
// socket, which needs Linux.
func Listen(network string, laddr *net.UDPAddr) (*net.UDPConn, *SendSocket, error) {
	c, err := net.ListenUDP(network, laddr)
	return c, nil, err
}

// NewSend returns nil, because a send socket needs Linux.
func NewSend(*SendSocket, int) *Batch { return nil }

// Sync does nothing.
func (*SendSocket) Sync() error { return nil }

// Close does nothing.
func (*SendSocket) Close() error { return nil }
