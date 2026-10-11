// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package relay

import "net"

// socketDrops reports false: only Linux gives the drop count of a socket.
func socketDrops(net.PacketConn) (uint64, bool) { return 0, false }
