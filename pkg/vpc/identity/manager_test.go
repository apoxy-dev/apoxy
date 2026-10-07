package identity

import (
	"cmp"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEnroller issues certs from ca with NotBefore = clock().
type fakeEnroller struct {
	t     *testing.T
	ca    *testCA
	clock func() time.Time
	calls int
	fail  bool
}

func (f *fakeEnroller) enroll(context.Context) (*Credential, error) {
	f.calls++
	if f.fail {
		return nil, errors.New("apiserver is down")
	}
	return issueWithRelays(f.t, f.ca, f.clock(), testRelays)
}

var testRelays = []Relay{{ID: "relay-1.example.com", Addresses: []string{"relay-1.example.com:443"}}}

// issueWithRelays issues a credential with NotBefore notBefore and relays.
func issueWithRelays(t *testing.T, ca *testCA, notBefore time.Time, relays []Relay) (*Credential, error) {
	key := newKey(t)
	c, err := NewCredential(key, certPEM(ca.issue(t, &key.PublicKey, testID, notBefore)), ca.pem)
	if err != nil {
		return nil, err
	}
	return c, c.SetRelays(relays, ca.pem)
}

func TestManagerStart(t *testing.T) {
	ca := newTestCA(t, "ca")
	cases := []struct {
		name       string
		cachedAt   time.Duration // cert NotBefore relative to now; zero means no cache
		renewAt    time.Duration // Renew time of the cached cert after its NotBefore. Zero means 16 h.
		noRelays   bool          // The cached cert has no relays.
		down       bool          // Enroll fails.
		wantEnroll bool
		wantCached bool // Start keeps the cached cert.
		wantErr    bool
	}{
		{name: "no cache", wantEnroll: true},
		{name: "fresh cache", cachedAt: -time.Hour, wantCached: true},
		{name: "cache with no relays", cachedAt: -time.Hour, noRelays: true, wantEnroll: true},
		{name: "cache past renew time", cachedAt: -17 * time.Hour, wantEnroll: true},
		{name: "cache before a late renew time", cachedAt: -17 * time.Hour, renewAt: 20*time.Hour - 1, wantCached: true},
		{name: "cache past an early renew time", cachedAt: -13 * time.Hour, renewAt: 12 * time.Hour, wantEnroll: true},
		{name: "cache before the earliest renew time", cachedAt: -11 * time.Hour, renewAt: 12 * time.Hour, wantCached: true},
		{name: "cache past the latest renew time", cachedAt: -20 * time.Hour, renewAt: 20*time.Hour - 1, wantEnroll: true},
		{name: "expired cache", cachedAt: -25 * time.Hour, wantEnroll: true},
		{name: "cache past renew time, apiserver down", cachedAt: -17 * time.Hour, down: true, wantEnroll: true, wantCached: true},
		{name: "expired cache, apiserver down", cachedAt: -25 * time.Hour, down: true, wantEnroll: true, wantErr: true},
		{name: "no cache, apiserver down", down: true, wantEnroll: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cred.json")
			now := func() time.Time { return testNow }
			renewAfter(t, cmp.Or(tc.renewAt, 16*time.Hour))
			var cached *Credential
			if tc.cachedAt != 0 {
				relays := testRelays
				if tc.noRelays {
					relays = nil
				}
				var err error
				cached, err = issueWithRelays(t, ca, testNow.Add(tc.cachedAt), relays)
				require.NoError(t, err)
				require.NoError(t, SaveCredential(path, cached))
			}
			f := &fakeEnroller{t: t, ca: ca, clock: now, fail: tc.down}
			m := NewManager(path, f.enroll, WithClock(now, time.After))
			err := m.Start(context.Background())
			if tc.wantEnroll {
				assert.Equal(t, 1, f.calls)
			} else {
				assert.Equal(t, 0, f.calls)
			}
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, m.Current())
				return
			}
			require.NoError(t, err)
			cur := m.Current()
			require.NotNil(t, cur)
			assert.Equal(t, testRelays, cur.Relays)
			// A second Start keeps the credential and does not enroll.
			require.NoError(t, m.Start(context.Background()))
			assert.Same(t, cur, m.Current())
			if tc.wantCached {
				assert.Equal(t, cached.Cert.Raw, cur.Cert.Raw)
				return
			}
			onDisk, err := LoadCredential(path)
			require.NoError(t, err)
			assert.Equal(t, cur.Cert.Raw, onDisk.Cert.Raw)
			assert.True(t, onDisk.Key.Equal(cur.Key))
			if cached != nil {
				assert.False(t, cur.Key.Equal(cached.Key), "renew must use a new key")
			}
		})
	}
}

func TestManagerRun(t *testing.T) {
	renewAfter(t, 14*time.Hour)
	ca := newTestCA(t, "ca")
	path := filepath.Join(t.TempDir(), "cred.json")
	now := testNow
	clock := func() time.Time { return now }
	waits := make(chan time.Duration)
	fire := make(chan time.Time)
	after := func(d time.Duration) <-chan time.Time {
		waits <- d
		return fire
	}
	f := &fakeEnroller{t: t, ca: ca, clock: clock}
	m := NewManager(path, f.enroll, WithClock(clock, after), WithRetryDelay(time.Minute))
	require.NoError(t, m.Start(context.Background()))
	first := m.Current()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- m.Run(ctx) }()

	// The first wait ends at the renew time of the cert.
	assert.Equal(t, 14*time.Hour, <-waits)
	now = now.Add(14 * time.Hour)
	f.fail = true
	fire <- now

	// A failed renew waits the retry delay.
	assert.Equal(t, time.Minute, <-waits)
	f.fail = false
	now = now.Add(time.Minute)
	fire <- now

	// After a renew the next wait ends at the renew time of the new cert.
	assert.Equal(t, 14*time.Hour, <-waits)
	second := m.Current()
	assert.False(t, second.Key.Equal(first.Key))
	assert.True(t, second.Cert.NotBefore.Equal(now))
	onDisk, err := LoadCredential(path)
	require.NoError(t, err)
	assert.Equal(t, second.Cert.Raw, onDisk.Cert.Raw)
	assert.Equal(t, 3, f.calls)

	cancel()
	assert.ErrorIs(t, <-done, context.Canceled)
}
