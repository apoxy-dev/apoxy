package logtail

import "golang.org/x/sys/unix"

// punchHole deallocates the byte range [off, off+len) in the file without
// changing its reported size (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE).
func punchHole(fd int, off, length int64) error {
	return unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, off, length)
}

// collapseRange removes the byte range [0, length) from the file, shrinking
// its reported size. Only valid on filesystem block boundaries.
func collapseRange(fd int, length int64) error {
	return unix.Fallocate(fd, unix.FALLOC_FL_COLLAPSE_RANGE, 0, length)
}
