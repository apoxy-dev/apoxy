// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package psp

import "net"

// acceptZeroSum does nothing. macOS has no option to accept IPv6 UDP packets with checksum 0.
func acceptZeroSum(*net.UDPConn) error { return nil }
