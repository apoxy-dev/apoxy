package identity

import (
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
	key := newKey(f.t)
	return NewCredential(key, certPEM(f.ca.issue(f.t, &key.PublicKey, testID, f.clock())), f.ca.pem)
}

func TestManagerStart(t *testing.T) {
	ca := newTestCA(t, "ca")
	cases := []struct {
		name       string
		cachedAt   time.Duration // cert NotBefore relative to now; zero means no cache
		wantEnroll bool
	}{
		{name: "no cache", wantEnroll: true},
		{name: "fresh cache", cachedAt: -time.Hour},
		{name: "cache past renew time", cachedAt: -17 * time.Hour, wantEnroll: true},
		{name: "expired cache", cachedAt: -25 * time.Hour, wantEnroll: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cred.json")
			now := func() time.Time { return testNow }
			var cached *Credential
			if tc.cachedAt != 0 {
				key := newKey(t)
				var err error
				cached, err = NewCredential(key, certPEM(ca.issue(t, &key.PublicKey, testID, testNow.Add(tc.cachedAt))), ca.pem)
				require.NoError(t, err)
				require.NoError(t, SaveCredential(path, cached))
			}
			f := &fakeEnroller{t: t, ca: ca, clock: now}
			m := NewManager(path, f.enroll, WithClock(now, time.After))
			require.NoError(t, m.Start(context.Background()))

			cur := m.Current()
			require.NotNil(t, cur)
			if !tc.wantEnroll {
				assert.Equal(t, 0, f.calls)
				assert.Equal(t, cached.Cert.Raw, cur.Cert.Raw)
				return
			}
			assert.Equal(t, 1, f.calls)
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

	// The first wait ends at 2/3 of the cert life.
	assert.Equal(t, 16*time.Hour, <-waits)
	now = now.Add(16 * time.Hour)
	f.fail = true
	fire <- now

	// A failed renew waits the retry delay.
	assert.Equal(t, time.Minute, <-waits)
	f.fail = false
	now = now.Add(time.Minute)
	fire <- now

	// After a renew the next wait is 2/3 of the new cert life.
	assert.Equal(t, 16*time.Hour, <-waits)
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
