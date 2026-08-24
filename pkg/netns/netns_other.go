// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package netns

import (
	"github.com/vishvananda/netns"
)

// isLiveNetns is unreachable off linux: GetFromName returns
// ErrNotImplemented there, so EnsureNamed never has a handle to validate.
// The stub keeps the package compiling everywhere.
func isLiveNetns(netns.NsHandle) bool {
	return true
}
