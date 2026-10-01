package identity

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

// EnrollFunc gets a new credential with a new key.
type EnrollFunc func(ctx context.Context) (*Credential, error)

// Manager keeps a valid agent credential. It uses the disk cache when the
// cached cert is before its renew time, and renews with a new key at 2/3 of
// the cert life.
type Manager struct {
	path       string
	enroll     EnrollFunc
	now        func() time.Time
	after      func(time.Duration) <-chan time.Time
	retryDelay time.Duration
	cur        atomic.Pointer[Credential]
}

// ManagerOption changes a Manager.
type ManagerOption func(*Manager)

// WithClock sets the clock. Tests use it.
func WithClock(now func() time.Time, after func(time.Duration) <-chan time.Time) ManagerOption {
	return func(m *Manager) {
		m.now = now
		m.after = after
	}
}

// WithRetryDelay sets the wait after a failed renew. The default is 30 s.
func WithRetryDelay(d time.Duration) ManagerOption {
	return func(m *Manager) { m.retryDelay = d }
}

// NewManager returns a Manager that caches the credential at path.
func NewManager(path string, enroll EnrollFunc, opts ...ManagerOption) *Manager {
	m := &Manager{
		path:       path,
		enroll:     enroll,
		now:        time.Now,
		after:      time.After,
		retryDelay: 30 * time.Second,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Start loads the cached credential, or enrolls when the cache has no cert
// that is before its renew time.
func (m *Manager) Start(ctx context.Context) error {
	c, err := LoadCredential(m.path)
	switch {
	case err == nil && m.now().Before(c.RenewAt()):
		m.cur.Store(c)
		return nil
	case err == nil:
		slog.Debug("Cached agent cert is due for renewal", "path", m.path, "renew_at", c.RenewAt())
	default:
		slog.Debug("No usable cached agent cert", "path", m.path, "error", err)
	}
	return m.Renew(ctx)
}

// Renew enrolls again with a new key and writes the cache. Callers also use
// it when a relay does not accept the cert, for example after a CA change.
func (m *Manager) Renew(ctx context.Context) error {
	c, err := m.enroll(ctx)
	if err != nil {
		return err
	}
	m.cur.Store(c)
	// The cache only saves an enroll at the next start, so a failed write
	// does not fail the renew.
	if err := SaveCredential(m.path, c); err != nil {
		slog.Warn("Failed to write the agent cert cache", "path", m.path, "error", err)
	}
	return nil
}

// Run renews the credential at its renew time until ctx ends. After a
// failed renew it tries again after the retry delay. Start must succeed first.
func (m *Manager) Run(ctx context.Context) error {
	if m.cur.Load() == nil {
		return errors.New("agent credential is not loaded")
	}
	failed := false
	for {
		wait := max(m.cur.Load().RenewAt().Sub(m.now()), 0)
		if failed {
			wait = max(wait, m.retryDelay)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.after(wait):
		}
		err := m.Renew(ctx)
		failed = err != nil
		if failed {
			slog.Warn("Failed to renew the agent cert", "path", m.path, "error", err)
			continue
		}
		c := m.cur.Load()
		slog.Info("Renewed the agent cert", "id", c.ID.String(), "expires_at", c.Cert.NotAfter)
	}
}

// Current returns the credential in use, or nil before Start.
func (m *Manager) Current() *Credential { return m.cur.Load() }

// GetClientCertificate is for tls.Config.GetClientCertificate.
func (m *Manager) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.tlsCertificate()
}

// GetCertificate is for tls.Config.GetCertificate in peer sessions.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.tlsCertificate()
}

func (m *Manager) tlsCertificate() (*tls.Certificate, error) {
	c := m.cur.Load()
	if c == nil {
		return nil, errors.New("agent credential is not loaded")
	}
	return c.TLSCertificate(), nil
}
