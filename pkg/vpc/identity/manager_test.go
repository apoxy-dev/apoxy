package identity

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	return issueFor(t, ca, testID, notBefore, relays)
}

// issueFor issues a credential for id with NotBefore notBefore and relays.
func issueFor(t *testing.T, ca *testCA, id ID, notBefore time.Time, relays []Relay) (*Credential, error) {
	key := newKey(t)
	c, err := NewCredential(key, certPEM(ca.issue(t, &key.PublicKey, id, notBefore)), ca.pem)
	if err != nil {
		return nil, err
	}
	return c, c.SetRelays(relays, ca.pem)
}

// logBuffer keeps the log lines of a test.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// count returns the number of log lines with the message msg.
func (b *logBuffer) count(msg string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Count(b.buf.String(), "msg="+strconv.Quote(msg))
}

// captureLogs sends the default log output to a buffer until the test ends.
func captureLogs(t *testing.T) *logBuffer {
	t.Helper()
	old, b := slog.Default(), &logBuffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(b, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return b
}

// identityFile is the content of an identity file in a test.
type identityFile struct {
	age      time.Duration // Time from NotBefore of the cert to testNow.
	id       ID            // Zero means testID.
	noRelays bool
	junk     bool        // The file does not parse.
	missing  bool        // No file.
	mode     os.FileMode // Zero means 0600.
}

// write puts the file at path and returns its credential, or nil.
func (f identityFile) write(t *testing.T, ca *testCA, path string) *Credential {
	t.Helper()
	_ = os.Remove(path)
	switch {
	case f.missing:
		return nil
	case f.junk:
		require.NoError(t, os.WriteFile(path, []byte("{junk"), 0o600))
		return nil
	}
	relays := testRelays
	if f.noRelays {
		relays = nil
	}
	c, err := issueFor(t, ca, cmp.Or(f.id, testID), testNow.Add(-f.age), relays)
	require.NoError(t, err)
	require.NoError(t, SaveCredential(path, c))
	if f.mode != 0 {
		require.NoError(t, os.Chmod(path, f.mode))
	}
	return c
}

const (
	otherUsersWarning = "Identity file has a private key and other users can read it"
	refusedWarning    = "Failed to use the new identity file"
	staleWarning      = "Identity file has no new certificate"
)

func TestFileManagerStart(t *testing.T) {
	ca := newTestCA(t, "ca")
	cases := []struct {
		name        string
		file        identityFile
		wantErr     string // A part of the error. Empty means no error.
		wantExpired bool   // The error is an ExpiredError.
		wantWarning bool   // A warning that other users can read the file.
	}{
		{name: "good file", file: identityFile{age: time.Hour}},
		{name: "file past the renew time of an agent that enrolls", file: identityFile{age: 23 * time.Hour}},
		{name: "no file", file: identityFile{missing: true}, wantErr: "failed to load identity file"},
		{name: "file that does not parse", file: identityFile{junk: true}, wantErr: "failed to parse credential file"},
		{name: "expired cert", file: identityFile{age: 24 * time.Hour}, wantErr: "expired at 2026-09-30T12:00:00Z", wantExpired: true},
		{name: "no relays", file: identityFile{age: time.Hour, noRelays: true}, wantErr: "has no relays"},
		{name: "file that other users can read", file: identityFile{age: time.Hour, mode: 0o644}, wantWarning: true},
		{name: "file that the group can read", file: identityFile{age: time.Hour, mode: 0o440}, wantWarning: true},
		{name: "read-only file of the owner", file: identityFile{age: time.Hour, mode: 0o400}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			path := filepath.Join(t.TempDir(), "identity.json")
			want := tc.file.write(t, ca, path)
			m := NewFileManager(path, WithClock(func() time.Time { return testNow }, time.After))
			require.True(t, m.FromFile())
			err := m.Start(context.Background())
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.ErrorContains(t, err, path)
				var expired *ExpiredError
				assert.Equal(t, tc.wantExpired, errors.As(err, &expired))
				assert.Nil(t, m.Current())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, want.Cert.Raw, m.Current().Cert.Raw)
			assert.Equal(t, testRelays, m.Current().Relays)
			wantWarnings := 0
			if tc.wantWarning {
				wantWarnings = 1
			}
			assert.Equal(t, wantWarnings, logs.count(otherUsersWarning))
		})
	}
}

// TestFileManagerReload replaces the identity file of a manager and reads it
// again with Renew, as an agent does when a relay refuses its cert.
func TestFileManagerReload(t *testing.T) {
	ca := newTestCA(t, "ca")
	otherVPC, otherProject, otherName := testID, testID, testID
	otherVPC.VPC = "11111111-2222-3333-4444-555555555555"
	otherProject.Project = "99999999-2222-3333-4444-555555555555"
	otherName.Agent = "fleet-2"
	cases := []struct {
		name    string
		next    *identityFile // The file that replaces the first one. Nil keeps the first file.
		wantNew bool
		wantErr string // A part of the error. Empty means no error.
	}{
		{name: "same file"},
		{name: "cert that expires later", next: &identityFile{age: time.Hour}, wantNew: true},
		{name: "cert that expires later, with a new identity name", next: &identityFile{age: time.Hour, id: otherName}, wantNew: true},
		{name: "cert that expires earlier", next: &identityFile{age: 3 * time.Hour}, wantErr: "is not later than the certificate in use"},
		{name: "cert for a different VPC", next: &identityFile{age: time.Hour, id: otherVPC}, wantErr: "is for VPC " + otherVPC.VPC},
		{name: "cert for a different project", next: &identityFile{age: time.Hour, id: otherProject}, wantErr: "of project " + otherProject.Project},
		{name: "file that does not parse", next: &identityFile{junk: true}, wantErr: "failed to parse credential file"},
		{name: "file with no relays", next: &identityFile{age: time.Hour, noRelays: true}, wantErr: "has no relays"},
		{name: "no file", next: &identityFile{missing: true}, wantErr: "failed to load identity file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity.json")
			first := identityFile{age: 2 * time.Hour}.write(t, ca, path)
			m := NewFileManager(path, WithClock(func() time.Time { return testNow }, time.After))
			require.NoError(t, m.Start(context.Background()))
			var next *Credential
			if tc.next != nil {
				next = tc.next.write(t, ca, path)
			}
			err := m.Renew(context.Background())
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.ErrorContains(t, err, path)
			} else {
				require.NoError(t, err)
			}
			changed := false
			select {
			case <-m.Changed():
				changed = true
			default:
			}
			assert.Equal(t, tc.wantNew, changed, "a value on Changed")
			if !tc.wantNew {
				assert.Equal(t, first.Cert.Raw, m.Current().Cert.Raw, "the manager keeps the first cert")
				return
			}
			assert.Equal(t, next.Cert.Raw, m.Current().Cert.Raw)
			// A second read of the same file changes nothing.
			cur := m.Current()
			require.NoError(t, m.Renew(context.Background()))
			assert.Same(t, cur, m.Current())
			assert.Empty(t, m.Changed())
		})
	}
}

// TestFileManagerRun runs a manager with an identity file on a fixed clock.
// Each step sets the time, can replace the file, and then lets one poll pass.
func TestFileManagerRun(t *testing.T) {
	const poll = 30 * time.Second
	ca := newTestCA(t, "ca")
	logs := captureLogs(t)
	path := filepath.Join(t.TempDir(), "identity.json")
	now := testNow
	clock := func() time.Time { return now }
	waits := make(chan time.Duration)
	fire := make(chan time.Time)
	after := func(d time.Duration) <-chan time.Time {
		waits <- d
		return fire
	}
	// The first cert is from testNow to testNow + 24 h.
	first := identityFile{}.write(t, ca, path)
	m := NewFileManager(path, WithClock(clock, after), WithPollInterval(poll))
	require.NoError(t, m.Start(context.Background()))
	done := make(chan error)
	go func() { done <- m.Run(context.Background()) }()
	require.Equal(t, poll, <-waits)

	// The second cert is from testNow + 1 h to testNow + 25 h.
	var second *Credential
	steps := []struct {
		name        string
		at          time.Duration // Time of the poll after testNow.
		file        *identityFile // Replaces the file before the poll.
		firstFile   bool          // The first file replaces the file before the poll.
		wantSecond  bool          // The manager uses the second cert after the poll.
		wantRefused int           // Warnings for a file that the manager did not use.
		wantStale   int           // Warnings for a file with no new cert.
		wantWait    time.Duration // The wait after the poll. Zero means the poll interval.
	}{
		{name: "same file", at: 30 * time.Second},
		{name: "bad file", at: time.Minute, file: &identityFile{junk: true}, wantRefused: 1},
		{name: "same bad file", at: 90 * time.Second, wantRefused: 1},
		{name: "file with an older cert", at: 2 * time.Minute, file: &identityFile{age: time.Hour}, wantRefused: 2},
		{name: "first file again", at: 150 * time.Second, firstFile: true, wantRefused: 2},
		{name: "file with a newer cert", at: time.Hour, file: &identityFile{age: -time.Hour}, wantSecond: true, wantRefused: 2},
		{name: "before 2/3 of the life of the second cert", at: 17*time.Hour - time.Second, wantSecond: true, wantRefused: 2},
		{name: "at 2/3 of the life", at: 17 * time.Hour, wantSecond: true, wantRefused: 2, wantStale: 1},
		{name: "less than one hour after the warning", at: 18*time.Hour - time.Second, wantSecond: true, wantRefused: 2, wantStale: 1},
		{name: "one hour after the warning", at: 18 * time.Hour, wantSecond: true, wantRefused: 2, wantStale: 2},
		{name: "10 s before the cert expires", at: 25*time.Hour - 10*time.Second, wantSecond: true, wantRefused: 2, wantStale: 3, wantWait: 10 * time.Second},
	}
	for _, st := range steps {
		now = testNow.Add(st.at)
		switch {
		case st.firstFile:
			require.NoError(t, SaveCredential(path, first))
		case st.file != nil:
			if c := st.file.write(t, ca, path); st.wantSecond {
				second = c
			}
		}
		fire <- now
		// Run asks for the next wait after it wrote the logs of this poll.
		require.Equal(t, cmp.Or(st.wantWait, poll), <-waits, st.name)
		want := first
		if st.wantSecond {
			want = second
		}
		assert.Equal(t, want.Cert.Raw, m.Current().Cert.Raw, st.name)
		assert.Equal(t, st.wantRefused, logs.count(refusedWarning), st.name)
		assert.Equal(t, st.wantStale, logs.count(staleWarning), st.name)
	}
	assert.Len(t, m.Changed(), 1, "one new identity file")

	// The cert expires and the file has no new cert.
	now = testNow.Add(25 * time.Hour)
	fire <- now
	err := <-done
	var expired *ExpiredError
	require.ErrorAs(t, err, &expired)
	assert.Equal(t, path, expired.Path)
	assert.True(t, expired.At.Equal(second.Cert.NotAfter))
	assert.EqualError(t, err, "the certificate in identity file "+path+" expired at 2026-10-01T13:00:00Z")
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
