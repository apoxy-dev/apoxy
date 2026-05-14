package apiserviceproxy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
)

// reloadDebounce coalesces the burst of events kubelet emits when it
// rewrites a Secret-mount dir (tls.crt, tls.key, ca.crt all change, plus
// the ..data symlink swap). 200ms is well below the kubelet sync floor
// and well above filesystem-event jitter.
const reloadDebounce = 200 * time.Millisecond

// runCertWatcher watches dir for Secret-mount updates and atomically swaps
// the live bundle on every successful reload. Returns when ctx is done.
//
// If dir doesn't exist or can't be watched (e.g. an older onboarding
// manifest that doesn't mount the Secret), runCertWatcher logs once at
// info and returns nil — hot-reload is best-effort and shouldn't fail the
// pod.
func runCertWatcher(
	ctx context.Context,
	dir string,
	store *certStore,
	onSwap func(*certBundle),
) error {
	if dir == "" {
		slog.Info("Upstream cert hot-reload disabled (no cert dir configured)")
		return nil
	}
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			slog.Info("Upstream cert directory missing; hot-reload disabled", "dir", dir)
			return nil
		}
		return fmt.Errorf("stat cert dir %s: %w", dir, err)
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create fsnotify watcher: %w", err)
	}
	defer w.Close()
	// Watch the parent dir, not tls.crt directly: kubelet's atomic update
	// is a symlink swap on ..data, which Create/Rename on the dir but
	// doesn't fire Write on the (now-stale) tls.crt inode.
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("watch cert dir %s: %w", dir, err)
	}
	slog.Info("Watching upstream cert directory", "dir", dir)

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
			slog.Warn("Cert watcher error", "err", err)
		case <-debounceFire:
			debounceFire = nil
			reloadOnce(dir, store, onSwap)
		}
	}
}

// reloadOnce reads + validates the on-disk bundle and, on success, swaps
// it in. Any failure keeps the live bundle untouched and bumps the
// failure counter so an operator can alert on partial-write or
// kubelet-projection races without the pod crashlooping.
func reloadOnce(dir string, store *certStore, onSwap func(*certBundle)) {
	b, err := loadBundleFromDisk(dir)
	if err != nil {
		certReloads.WithLabelValues(resultFailure).Inc()
		slog.Error("Failed to reload upstream cert", "dir", dir, "err", err)
		return
	}
	if cur := store.Load(); cur != nil && cur.fp == b.fp {
		// Same generation — kubelet sometimes rewrites identical content
		// on resync. No-op, don't bump the counter (would be misleading).
		return
	}
	store.Store(b)
	certReloads.WithLabelValues(resultSuccess).Inc()
	certExpiry.Set(float64(b.notAfter.Unix()))
	slog.Info(
		"Reloaded upstream client cert",
		"fingerprint", b.fp,
		"not_after", b.notAfter.UTC().Format(time.RFC3339),
	)
	if onSwap != nil {
		onSwap(b)
	}
}
