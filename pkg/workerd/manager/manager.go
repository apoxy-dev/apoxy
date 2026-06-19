// SPDX-License-Identifier: AGPL-3.0-only

package manager

import "time"

// Requeue intervals for the control-plane reconciler's polling waits. These are
// short, bounded waits for state another controller (the resident reconciler /
// a build) is expected to produce soon — not hot loops.
const (
	// requeueAwaitBuild is how long to wait before re-checking for a revision's
	// bundle to become pullable/resolvable (a build or a slow registry).
	requeueAwaitBuild = 15 * time.Second
)
