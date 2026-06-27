package reload

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"
)

// startupLoadAttempts / startupLoadDelay bound the retry on the initial load.
// A (re)start that coincides with an in-progress rotation can briefly see a
// torn or half-written keypair; the runtime watcher already tolerates that
// by keeping the last good bundle, so the constructor matches that tolerance
// rather than crash-looping the pod. The window is small, so the total wait
// stays short while a genuinely-absent cert still fails fast enough.
const (
	startupLoadAttempts = 5
	startupLoadDelay    = 200 * time.Millisecond
)

// Reloader serves a TLS server certificate from disk and hot-reloads it when
// the backing files rotate (e.g. cert-manager rewriting a Kubernetes
// Secret). GetCertificate reads are lock-free atomic-pointer loads with no
// syscalls — a background watcher (Start) does all the disk work — so they
// stay cheap on the handshake-accept hot path.
//
// Wire GetCertificate into tls.Config.GetCertificate and run Start in a
// goroutine (or add it to a controller-runtime manager as a Runnable).
type Reloader struct {
	paths Paths
	store *Store
	opts  WatchOptions
}

// NewReloader loads the initial bundle (retrying briefly past a torn-write
// race) so construction fails fast on a genuinely missing/malformed keypair,
// and returns a Reloader ready to serve it. component labels the metrics and
// logs; metrics default to the shared apoxy_tls_cert_* series.
func NewReloader(p Paths, component string) (*Reloader, error) {
	b, err := loadWithRetry(p)
	if err != nil {
		return nil, fmt.Errorf("load initial certificate: %w", err)
	}
	store := NewStore()
	store.Store(b)
	m := DefaultMetrics(component)
	m.ReloadAttempt(true)
	m.SetExpiry(b.NotAfter)
	return &Reloader{
		paths: p,
		store: store,
		opts: WatchOptions{
			Metrics:   m,
			Component: component,
		},
	}, nil
}

func loadWithRetry(p Paths) (*Bundle, error) {
	var err error
	for i := 0; i < startupLoadAttempts; i++ {
		var b *Bundle
		if b, err = LoadBundle(p); err == nil {
			return b, nil
		}
		if i < startupLoadAttempts-1 {
			slog.Warn("Initial cert load failed, retrying", "err", err)
			time.Sleep(startupLoadDelay)
		}
	}
	return nil, err
}

// GetCertificate implements tls.Config.GetCertificate, returning the live
// leaf from the atomic store with no disk access.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	b := r.store.Load()
	if b == nil {
		return nil, ErrNoCertificate
	}
	return &b.Cert, nil
}

// Bundle returns the live bundle (cert + root pool + expiry), or nil before
// the first load. Useful for client-side consumers that need RootCAs.
func (r *Reloader) Bundle() *Bundle { return r.store.Load() }

// Start runs the background watcher until ctx is done. Implements
// sigs.k8s.io/controller-runtime/pkg/manager.Runnable.
func (r *Reloader) Start(ctx context.Context) error {
	return Watch(ctx, r.paths, r.store, r.opts)
}
