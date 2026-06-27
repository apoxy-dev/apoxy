package reload

import (
	"errors"
	"sync/atomic"
)

// ErrNoCertificate is returned by Reloader.GetCertificate before any bundle
// has been successfully loaded.
var ErrNoCertificate = errors.New("reload: no certificate loaded")

// Store holds the live Bundle behind an atomic pointer so handshakes, the
// metrics emitter, and the watcher can all read/write without locks.
type Store struct {
	cur atomic.Pointer[Bundle]
}

// NewStore returns an empty Store.
func NewStore() *Store { return &Store{} }

// Load returns the current bundle, or nil if none has been stored.
func (s *Store) Load() *Bundle { return s.cur.Load() }

// Store publishes b as the current bundle in a single atomic swap.
func (s *Store) Store(b *Bundle) { s.cur.Store(b) }
