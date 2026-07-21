// Package logtail consumes log files and manages compaction using fallocate.
package logtail

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/fsnotify/fsnotify"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	blockSize = 4096
	trimSize  = 1024 * 1024
)

// Skip 0s at the beginning of the file (resulted from fallocate).
func skipZeroes(r *bufio.Reader, bufSize int) (int, error) {
	var consumed int
	for {
		data, err := r.Peek(bufSize)
		if len(data) == 0 {
			return consumed, err
		}

		for i := 0; i < len(data); i++ {
			if data[i] == 0 {
				continue
			}

			d, err := r.Discard(i)
			consumed += d
			if err != nil {
				return consumed, err
			}
			return consumed, nil
		}

		d, err := r.Discard(len(data))
		consumed += d
		if err != nil {
			return consumed, err
		}
	}
	panic("unreachable")
	return 0, nil
}

func waitForUpdate(ctx context.Context, watcher *fsnotify.Watcher) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if ev.Has(fsnotify.Write) {
				return nil
			}
		case err := <-watcher.Errors:
			return err
		}
	}
	panic("unreachable")
}

// Tail returns a channel that will receive log lines as they are written to the log file.
// The channel will be closed when the context is canceled.
func Tail(ctx context.Context, path string, cb func([]byte) error) error {
	log.Infof("Tailing file %s", path)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	if err := watcher.Add(path); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	r := bufio.NewReader(f)
	// Skip 0s at the beginning of the file which may have resulted from
	// trimming the file using FALLOC_FL_COLLAPSE_RANGE.
	consumed, err := skipZeroes(r, 1024)
	if err != nil && err != io.EOF {
		return err
	}

	log.Infof("Skipping %d bytes of zeroes at the beginning of the file", consumed)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			logLine, err := r.ReadBytes('\n')
			if err != nil && err != io.EOF {
				return err
			}

			log.Infof("Read %d bytes from the file", len(logLine))

			if len(logLine) > 0 {
				if err := cb(logLine); err != nil {
					return fmt.Errorf("callback: %w", err)
				}
				if err := punchHole(int(f.Fd()), int64(consumed), int64(len(logLine))); err != nil {
					return fmt.Errorf("punching hole: %w", err)
				}
				consumed += len(logLine)

				// If the hole has reached the trim size, collapse it. This will
				// reduce the reported file size (as seen by stat call).
				// Can only be done on fs block boundaries on most filesystems.
				if consumed >= trimSize {
					ts := consumed / blockSize * blockSize // Round down to the nearest block size.
					if err := collapseRange(int(f.Fd()), int64(ts)); err != nil {
						return fmt.Errorf("collapsing file: %w", err)
					}
					log.Infof("Collapsed range: [0, %d)", ts)
					// FALLOC_FL_COLLAPSE_RANGE doesn't change the fd offset, so we need to re-open the file and
					// skip the zeroes again.
					if err := f.Close(); err != nil {
						return err
					}
					f, err = os.OpenFile(path, os.O_RDWR, 0644)
					if err != nil {
						return err
					}
					r = bufio.NewReader(f)
					consumed, err = skipZeroes(r, 1024)
					if err != nil && err != io.EOF {
						return err
					}
				}
			} else { // Empty line means EOF.
				if err := waitForUpdate(ctx, watcher); err != nil {
					return fmt.Errorf("waiting for file update: %w", err)
				}
				log.Infof("File %s updated", path)
			}
		}
	}
	panic("unreachable")
}
