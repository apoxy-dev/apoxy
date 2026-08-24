// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package netns

import (
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netns"
)

// isLiveNetns reports whether the handle refers to a live network namespace.
// A handle from GetFromName is only an open fd on /run/netns/<name>; when the
// bind mount behind that path did not survive a node reboot, the fd refers to
// a plain file on the volume's filesystem and every later setns() on it fails
// with EINVAL. A live namespace fd is always backed by the kernel's nsfs, so
// the filesystem magic separates the two exactly. This is the same check
// containerd and CRI-O run (through containernetworking/plugins ns.GetNS)
// before they trust a recovered sandbox namespace.
func isLiveNetns(ns netns.NsHandle) bool {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(ns), &st); err != nil {
		return false
	}
	return st.Type == unix.NSFS_MAGIC
}
