// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package relay

import "net"

// batchWrites reports whether x/net sends a batch with one sendmmsg call.
const batchWrites = false

func gsoSupported(*net.UDPConn) bool { return false }

func appendSegmentSize(b []byte, _ uint16) []byte { return b }

func isGSOError(error) bool { return false }
