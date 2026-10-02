// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package agent

import (
	"net"
	"os"
)

// peerUID returns this user. Only the socket file mode limits the callers.
func peerUID(net.Conn) (int, error) { return os.Getuid(), nil }
