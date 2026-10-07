// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// errAny matches any error in the tables.
var errAny = errors.New("any error")

func TestCheckCert(t *testing.T) {
	ca, other := newCA(t), newCA(t)
	laptop := agentID(vpcA, "laptop")
	issued := t0.Add(-time.Hour)
	cases := []struct {
		name  string
		cert  tls.Certificate
		trust func(*fakeTrust) // Changes the trust data. Nil keeps it.
		now   time.Time
		want  error // Nil means the check passes.
	}{
		{"good", ca.issue(t, laptop, issued), nil, t0, nil},
		{"wrong CA", other.issue(t, laptop, issued), nil, t0, errAny},
		{"CA of the project", other.issue(t, laptop, issued), func(f *fakeTrust) {
			f.projectCA = map[string]*testCA{vpcA.Project: other}
		}, t0, nil},
		{"CA of another project", other.issue(t, laptop, issued), func(f *fakeTrust) {
			f.projectCA = map[string]*testCA{vpcA.Project: ca, vpcB.Project: other}
		}, t0, errAny},
		{"CA that the project had before", ca.issue(t, laptop, issued), func(f *fakeTrust) {
			f.projectCA = map[string]*testCA{vpcA.Project: other}
		}, t0, errAny},
		{"project with no CA", ca.issue(t, laptop, issued), func(f *fakeTrust) {
			f.projectCA = map[string]*testCA{vpcA.Project: nil}
		}, t0, errAny},
		{"expired", ca.issue(t, laptop, issued), nil, issued.Add(identity.CertLifetime + time.Second), errAny},
		{"not yet valid", ca.issue(t, laptop, issued), nil, issued.Add(-time.Second), errAny},
		{"revoked", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.revoke(vpcA, "laptop", t0) }, t0, identity.ErrRevoked},
		{"revoked before the cert", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.revoke(vpcA, "laptop", issued.Add(-time.Minute)) }, t0, nil},
		{"revoked in another VPC", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.revoke(vpcB, "laptop", t0) }, t0, nil},
		{"other agent revoked", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.revoke(vpcA, "phone", t0) }, t0, nil},
		{"no SPIFFE SAN", ca.issue(t, "", issued), nil, t0, errAny},
		{"SAN not an agent ID", ca.issue(t, "spiffe://project-a/workload/x", issued), nil, t0, errAny},
		{"trust data too old", ca.issue(t, laptop, issued), func(f *fakeTrust) { f.err = errors.New("snapshot too old") }, t0, errAny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trust := &fakeTrust{ca: ca}
			if tc.trust != nil {
				tc.trust(trust)
			}
			id, err := NewRouter(trust, Config{}).checkCert([]*x509.Certificate{tc.cert.Leaf}, tc.now)
			switch tc.want {
			case nil:
				require.NoError(t, err)
				assert.Equal(t, laptop, id.String())
			case errAny:
				assert.Error(t, err)
			default:
				assert.ErrorIs(t, err, tc.want)
			}
		})
	}

	t.Run("no cert", func(t *testing.T) {
		_, err := NewRouter(&fakeTrust{ca: ca}, Config{}).checkCert(nil, t0)
		assert.Error(t, err)
	})
	t.Run("no trust data", func(t *testing.T) {
		_, err := NewRouter(nil, Config{}).checkCert([]*x509.Certificate{ca.issue(t, laptop, issued).Leaf}, t0)
		assert.Error(t, err)
	})
}

// TestHandshake checks that a cert that fails the check fails the QUIC
// handshake, so the relay serves no call on it.
func TestHandshake(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	h.trust.revoke(vpcA, "revoked", time.Now())
	cases := []struct {
		name string
		cert tls.Certificate
		alpn string
		ok   bool
	}{
		{"good", ca.agentCert(t, vpcA, "laptop"), dp.ALPNRelay, true},
		{"wrong CA", newCA(t).agentCert(t, vpcA, "laptop"), dp.ALPNRelay, false},
		{"expired", ca.issue(t, agentID(vpcA, "laptop"), time.Now().Add(-identity.CertLifetime-time.Minute)), dp.ALPNRelay, false},
		{"revoked", ca.agentCert(t, vpcA, "revoked"), dp.ALPNRelay, false},
		{"no SPIFFE SAN", ca.issue(t, "", time.Now().Add(-time.Hour)), dp.ALPNRelay, false},
		{"no client cert", tls.Certificate{}, dp.ALPNRelay, false},
		{"peer ALPN", ca.agentCert(t, vpcA, "laptop"), dp.ALPNPeer, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := h.dial(t, tc.cert, tc.alpn)
			if !tc.ok {
				requireRefused(t, a, err)
				return
			}
			require.NoError(t, err)
			s := h.session(t, a)
			assert.Equal(t, Identity{VPC: vpcA, ID: agentID(vpcA, "laptop")}, s.Identity())
		})
	}
}

// TestRecheck checks that a trust change closes the sessions whose cert now
// fails, and keeps the others.
func TestRecheck(t *testing.T) {
	cases := []struct {
		name   string
		change func(h *harness)
		closed bool
	}{
		{"no change", func(*harness) {}, false},
		{"agent revoked", func(h *harness) { h.trust.revoke(vpcA, "laptop", time.Now()) }, true},
		{"other agent revoked", func(h *harness) { h.trust.revoke(vpcA, "phone", time.Now()) }, false},
		{"CA removed", func(h *harness) { h.trust.setCA(newCA(t)) }, true},
		{"trust data too old", func(h *harness) {
			h.trust.mu.Lock()
			h.trust.err = errors.New("snapshot too old")
			h.trust.mu.Unlock()
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			h := newHarness(t, ca)
			a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
			h.session(t, a)
			tc.change(h)
			h.r.Recheck()
			if !tc.closed {
				time.Sleep(50 * time.Millisecond)
				assert.NoError(t, a.qc.Context().Err())
				return
			}
			assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_CERT), closeCode(t, a.qc))
		})
	}
}

// TestNotAfter checks that Sweep closes a session at the NotAfter of its cert.
func TestNotAfter(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	cert := ca.agentCert(t, vpcA, "laptop")
	a := h.mustDial(t, cert)
	h.session(t, a)
	h.r.Sweep(cert.Leaf.NotAfter.Add(-time.Second))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, a.qc.Context().Err())
	h.r.Sweep(cert.Leaf.NotAfter)
	assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_CERT), closeCode(t, a.qc))
}

// TestTrustChange checks that a change of the trust data applies to new
// sessions at once. Sessions that exist continue until Recheck.
func TestTrustChange(t *testing.T) {
	oldCA, newCA := newCA(t), newCA(t)
	h := newHarness(t, oldCA)
	first := h.mustDial(t, oldCA.agentCert(t, vpcA, "first"))
	h.session(t, first)

	h.trust.setCA(newCA)
	a, err := h.dial(t, oldCA.agentCert(t, vpcA, "second"))
	requireRefused(t, a, err) // Cert from the old CA.
	h.session(t, h.mustDial(t, newCA.agentCert(t, vpcA, "second")))

	h.trust.revoke(vpcA, "third", time.Now())
	a, err = h.dial(t, newCA.agentCert(t, vpcA, "third"))
	requireRefused(t, a, err) // Revoked agent.

	time.Sleep(50 * time.Millisecond)
	assert.NoError(t, first.qc.Context().Err(), "the session from the old CA continues")
	h.r.Recheck()
	assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_CERT), closeCode(t, first.qc))
}
