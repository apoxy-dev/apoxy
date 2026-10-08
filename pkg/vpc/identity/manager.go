package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// EnrollFunc gets a new credential with a new key.
type EnrollFunc func(ctx context.Context) (*Credential, error)

// Manager keeps a valid agent credential. It uses the disk cache when the
// cached cert is before its renew time, and renews with a new key at the
// renew time of the cert.
//
// A Manager from NewFileManager has no enroll function. Its credential comes
// from an identity file that another program replaces.
type Manager struct {
	path       string
	enroll     EnrollFunc // Nil with an identity file.
	now        func() time.Time
	after      func(time.Duration) <-chan time.Time
	retryDelay time.Duration
	cur        atomic.Pointer[Credential]

	poll     time.Duration // Time between two reads of the identity file.
	reloadMu sync.Mutex    // One read of the identity file at a time.
	changed  chan struct{} // Gets a value when a new identity file is in use.
}

// ExpiredError tells that the cert of an identity file expired, and that the
// file has no newer cert.
type ExpiredError struct {
	Path string
	At   time.Time
}

func (e *ExpiredError) Error() string {
	return fmt.Sprintf("the certificate in identity file %s expired at %s", e.Path, e.At.UTC().Format(time.RFC3339))
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

// WithPollInterval sets the time between two reads of the identity file. The
// default is 30 s.
func WithPollInterval(d time.Duration) ManagerOption {
	return func(m *Manager) { m.poll = d }
}

// NewManager returns a Manager that caches the credential at path.
func NewManager(path string, enroll EnrollFunc, opts ...ManagerOption) *Manager {
	m := &Manager{
		path:       path,
		enroll:     enroll,
		now:        time.Now,
		after:      time.After,
		retryDelay: 30 * time.Second,
		poll:       30 * time.Second,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// NewFileManager returns a Manager for the identity file at path. It never
// enrolls: the file comes from "apoxy alpha vpc enroll" or from a call to
// EnrollFile, and that program replaces it before the cert expires.
func NewFileManager(path string, opts ...ManagerOption) *Manager {
	m := NewManager(path, nil, opts...)
	m.changed = make(chan struct{}, 1)
	return m
}

// FromFile reports whether the credential comes from an identity file.
func (m *Manager) FromFile() bool { return m.enroll == nil }

// Changed gets a value each time the manager starts to use a new identity
// file. It is nil for a manager that enrolls.
func (m *Manager) Changed() <-chan struct{} { return m.changed }

// Start loads the cached credential, or enrolls when the cache has no cert
// with relays that is before its renew time. When that enroll fails, it uses
// the cached cert until it expires. After a success, Start does nothing.
//
// With an identity file, the file must have a cert that is not expired, and
// relays.
func (m *Manager) Start(ctx context.Context) error {
	if m.cur.Load() != nil {
		return nil
	}
	if m.enroll == nil {
		return m.startFile()
	}
	c, err := LoadCredential(m.path)
	switch {
	case err != nil:
		slog.Debug("No usable cached agent cert", "path", m.path, "error", err)
		return m.Renew(ctx)
	case len(c.Relays) == 0:
		slog.Debug("Cached agent cert has no relays", "path", m.path)
		return m.Renew(ctx)
	case m.now().Before(c.RenewAt()):
		m.cur.Store(c)
		return nil
	}
	slog.Debug("Cached agent cert is due for renewal", "path", m.path, "renew_at", c.RenewAt())
	err = m.Renew(ctx)
	if err != nil && m.now().Before(c.Cert.NotAfter) {
		slog.Warn("Failed to renew the cached agent cert; using it until it expires",
			"path", m.path, "expires_at", c.Cert.NotAfter, "error", err)
		m.cur.Store(c)
		return nil
	}
	return err
}

// startFile loads the identity file for Start.
func (m *Manager) startFile() error {
	c, err := m.loadFile()
	if err != nil {
		return err
	}
	if !m.now().Before(c.Cert.NotAfter) {
		return &ExpiredError{Path: m.path, At: c.Cert.NotAfter}
	}
	// A Secret volume has mode 0644 by default, so this is not an error.
	if fi, err := os.Stat(m.path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		slog.Warn("Identity file has a private key and other users can read it", "path", m.path, "mode", fi.Mode().Perm().String())
	}
	m.cur.Store(c)
	return nil
}

// loadFile reads the identity file. An agent cannot connect with no relays.
func (m *Manager) loadFile() (*Credential, error) {
	c, err := LoadCredential(m.path)
	if err != nil {
		return nil, fmt.Errorf("failed to load identity file %s: %w", m.path, err)
	}
	if len(c.Relays) == 0 {
		return nil, fmt.Errorf("identity file %s has no relays", m.path)
	}
	return c, nil
}

// reload reads the identity file again. The manager uses a new cert of the
// file when it is for the same project and VPC and expires later than the
// cert in use. reload reports whether the manager has a new credential.
func (m *Manager) reload() (bool, error) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	cur := m.cur.Load()
	c, err := m.loadFile()
	switch {
	case err != nil:
		return false, err
	case c.Cert.Equal(cur.Cert):
		return false, nil
	case c.ID.Project != cur.ID.Project || c.ID.VPC != cur.ID.VPC:
		return false, fmt.Errorf("identity file %s is for VPC %s of project %s, and the agent is in VPC %s of project %s",
			m.path, c.ID.VPC, c.ID.Project, cur.ID.VPC, cur.ID.Project)
	case !c.Cert.NotAfter.After(cur.Cert.NotAfter):
		return false, fmt.Errorf("the certificate in identity file %s expires at %s, which is not later than the certificate in use (%s)",
			m.path, c.Cert.NotAfter.UTC().Format(time.RFC3339), cur.Cert.NotAfter.UTC().Format(time.RFC3339))
	}
	m.cur.Store(c)
	select {
	case m.changed <- struct{}{}:
	default:
	}
	return true, nil
}

// staleAt is 2/3 of the life of cert. From this time, a manager with an
// identity file warns that the file has no new cert.
func staleAt(cert *x509.Certificate) time.Time {
	return cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 3 * 2)
}

// runFile reads the identity file again at each poll interval until ctx
// ends. It returns an ExpiredError when the cert in use expires.
func (m *Manager) runFile(ctx context.Context) error {
	var refused string   // Why the manager did not use the file at the last read.
	var warned time.Time // Time of the last warning for a file with no new cert.
	for {
		c, now := m.cur.Load(), m.now()
		left := c.Cert.NotAfter.Sub(now)
		if left <= 0 {
			return &ExpiredError{Path: m.path, At: c.Cert.NotAfter}
		}
		if !now.Before(staleAt(c.Cert)) && now.Sub(warned) >= time.Hour {
			slog.Warn("Identity file has no new certificate", "path", m.path, "expires_at", c.Cert.NotAfter)
			warned = now
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.after(min(m.poll, left)):
		}
		changed, err := m.reload()
		reason := ""
		if err != nil {
			reason = err.Error()
		}
		// One warning for each reason, not one for each read.
		if reason != "" && reason != refused {
			slog.Warn("Failed to use the new identity file", "error", err)
		}
		refused = reason
		if changed {
			c := m.cur.Load()
			slog.Info("Loaded a new identity file", "path", m.path, "id", c.ID.String(), "expires_at", c.Cert.NotAfter)
		}
	}
}

// Renew enrolls again with a new key and writes the cache. Callers also use
// it when a relay does not accept the cert, for example after a CA change.
// With an identity file, Renew reads the file again and does not enroll.
func (m *Manager) Renew(ctx context.Context) error {
	if m.enroll == nil {
		_, err := m.reload()
		return err
	}
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
//
// With an identity file, Run reads the file again at each poll interval. It
// returns an ExpiredError when the cert in use expires.
func (m *Manager) Run(ctx context.Context) error {
	if m.cur.Load() == nil {
		return errors.New("agent credential is not loaded")
	}
	if m.enroll == nil {
		return m.runFile(ctx)
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
