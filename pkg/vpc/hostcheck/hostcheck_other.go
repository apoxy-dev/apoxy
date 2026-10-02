// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package hostcheck

import "syscall"

// Check returns no warnings. The checks need Linux.
func Check(conn syscall.Conn, tun bool) []Warning { return nil }
