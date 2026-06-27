package reload

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// reloadDebounce coalesces the burst of events kubelet emits when it
// rewrites a Secret-mount dir (tls.crt, tls.key, ca.crt all change, plus the
// ..data symlink swap). 200ms is well below the kubelet sync floor and well
// above filesystem-event jitter.
const reloadDebounce = 200 * time.Millisecond

// resyncInterval forces a periodic disk re-check so a rotation that fails to
// fire an inotify event — a dropped event, an mtime-preserving rewrite, or a
// renewer that swaps files without touching the watched dir — is still
// picked up well before the live leaf expires. fsnotify is the fast path;
// this is the safety net.
const resyncInterval = 10 * time.Minute

// WatchOptions configures a watcher run.
type WatchOptions struct {
	// OnSwap, if set, is called after each successful bundle swap.
	OnSwap func(*Bundle)
	// Metrics records reload outcomes; nil disables metric recording.
	Metrics Metrics
	// Component labels this watcher's log lines.
	Component string
}

// Watch watches the directories holding p's files and atomically swaps the
// live bundle in store on every successful reload, until ctx is done. It
// also resyncs from disk periodically as a backstop against missed events.
//
// Watch is best-effort: if no directory can be watched (e.g. a pod whose
// Secret isn't mounted) it logs once and returns nil rather than failing the
// caller — hot-reload is an enhancement, not a hard dependency.
func Watch(ctx context.Context, p Paths, store *Store, opts WatchOptions) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create fsnotify watcher: %w", err)
	}
	defer w.Close()

	// Watch the parent dirs, not the files directly: kubelet's atomic update
	// is a symlink swap on ..data, which fires Create/Rename on the dir but
	// not Write on the (now-stale) tls.crt inode.
	watched := false
	for _, d := range watchDirs(p) {
		if _, err := os.Stat(d); err != nil {
			slog.Info("Cert directory missing; not watching", "component", opts.Component, "dir", d)
			continue
		}
		if err := w.Add(d); err != nil {
			slog.Warn("Failed to watch cert directory", "component", opts.Component, "dir", d, "err", err)
			continue
		}
		watched = true
	}
	if !watched {
		slog.Info("Cert hot-reload disabled (no watchable directory)", "component", opts.Component)
		return nil
	}
	slog.Info("Watching cert directories", "component", opts.Component, "dirs", watchDirs(p))

	resync := time.NewTicker(resyncInterval)
	defer resync.Stop()

	// debounceFire fires after the burst of inotify events settles, so a
	// single rotation produces one reload attempt rather than three.
	var debounceFire <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if !ev.Has(fsnotify.Create) && !ev.Has(fsnotify.Write) && !ev.Has(fsnotify.Rename) {
				continue
			}
			debounceFire = time.After(reloadDebounce)
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			slog.Warn("Cert watcher error", "component", opts.Component, "err", err)
		case <-debounceFire:
			debounceFire = nil
			reloadOnce(p, store, opts)
		case <-resync.C:
			reloadOnce(p, store, opts)
		}
	}
}

// reloadOnce reads + validates the on-disk bundle and, on success, swaps it
// in. Any failure keeps the live bundle untouched and records a failed
// attempt so an operator can alert on partial-write or projection races
// (and on a reload loop that never recovers) without the process
// crashlooping. Identical-content rewrites are deduped by fingerprint and
// recorded as neither success nor failure.
func reloadOnce(p Paths, store *Store, opts WatchOptions) {
	b, err := LoadBundle(p)
	if err != nil {
		if opts.Metrics != nil {
			opts.Metrics.ReloadAttempt(false)
		}
		slog.Error("Failed to reload cert", "component", opts.Component, "err", err)
		return
	}
	if cur := store.Load(); cur != nil && cur.Fingerprint == b.Fingerprint {
		// Same generation — kubelet sometimes rewrites identical content on
		// resync, and the periodic resync re-reads unchanged files. No-op.
		return
	}
	store.Store(b)
	if opts.Metrics != nil {
		opts.Metrics.ReloadAttempt(true)
		opts.Metrics.SetExpiry(b.NotAfter)
	}
	slog.Info("Reloaded cert",
		"component", opts.Component,
		"fingerprint", b.Fingerprint,
		"not_after", b.NotAfter.UTC().Format(time.RFC3339),
	)
	if opts.OnSwap != nil {
		opts.OnSwap(b)
	}
}

// watchDirs returns the unique parent directories of p's non-empty files.
func watchDirs(p Paths) []string {
	seen := map[string]bool{}
	var dirs []string
	for _, f := range []string{p.Cert, p.Key, p.CA} {
		if f == "" {
			continue
		}
		d := filepath.Dir(f)
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	return dirs
}
