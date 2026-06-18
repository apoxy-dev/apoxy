// SPDX-License-Identifier: AGPL-3.0-only

package manager

import "time"

// Requeue intervals for the control-plane reconciler's polling waits. These are
// short, bounded waits for state another controller (the resident reconciler /
// a build) is expected to produce soon — not hot loops.
const (
	// requeueAwaitBuild is how long to wait before re-checking for a build's
	// bundle (git source).
	requeueAwaitBuild = 15 * time.Second
	// requeueAwaitResident is how long to wait before re-checking whether the
	// target revision has become resident-ready so it can be promoted live.
	requeueAwaitResident = 5 * time.Second
)
