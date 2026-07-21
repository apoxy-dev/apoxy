//go:build !linux

package logtail

import "errors"

// Hole punching and range collapsing are Linux-only (fallocate). The tailer is
// only deployed on Linux; these stubs exist so the package compiles on other
// platforms for development builds.

func punchHole(fd int, off, length int64) error {
	return errors.New("hole punching is not supported on this platform")
}

func collapseRange(fd int, length int64) error {
	return errors.New("range collapsing is not supported on this platform")
}
