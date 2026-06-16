// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package host

// StartChildReaper is a no-op on non-linux platforms (there is no runsc/Sentry
// to orphan children here).
func StartChildReaper() {}
