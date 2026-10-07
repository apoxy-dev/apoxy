package identity

import (
	"crypto/x509"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCredential(t *testing.T) {
	renewAfter(t, 16*time.Hour)
	ca := newTestCA(t, "ca")
	key := newKey(t)
	other := newKey(t)
	cert := ca.issue(t, &key.PublicKey, testID, testNow)

	cases := []struct {
		name     string
		wrongKey bool
		cert     []byte
		bundle   []byte
		wantErr  bool
	}{
		{name: "valid", cert: certPEM(cert), bundle: ca.pem},
		{name: "cert for another key", wrongKey: true, cert: certPEM(cert), bundle: ca.pem, wantErr: true},
		{name: "no cert", bundle: ca.pem, wantErr: true},
		{name: "no bundle", cert: certPEM(cert), wantErr: true},
		{name: "bundle is a leaf", cert: certPEM(cert), bundle: certPEM(cert), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := key
			if tc.wrongKey {
				k = other
			}
			c, err := NewCredential(k, tc.cert, tc.bundle)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testID, c.ID)
			assert.Equal(t, testNow.Add(16*time.Hour), c.RenewAt())
		})
	}
}

func TestRenewTime(t *testing.T) {
	fixed := func(num, den time.Duration) func(time.Duration) time.Duration {
		return func(n time.Duration) time.Duration { return n * num / den }
	}
	cases := []struct {
		name   string
		life   time.Duration
		jitter func(n time.Duration) time.Duration // Nil means the random source.
		random bool                                // The time is in the range, and the times differ.
		want   time.Duration                       // Renew time after NotBefore.
	}{
		{name: "earliest", life: 24 * time.Hour, jitter: fixed(0, 1), want: 12 * time.Hour},
		{name: "middle", life: 24 * time.Hour, jitter: fixed(1, 2), want: 16 * time.Hour},
		{name: "latest", life: 24 * time.Hour, jitter: func(n time.Duration) time.Duration { return n - 1 }, want: 20*time.Hour - 1},
		{name: "short life", life: 3 * time.Second, jitter: fixed(1, 2), want: 2 * time.Second},
		// The random source does not take a range of zero or less.
		{name: "life with no range", life: 2, want: 1},
		{name: "no life", life: 0, want: 0},
		{name: "end before the start", life: -time.Hour, want: -30 * time.Minute},
		{name: "random", life: 24 * time.Hour, random: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.jitter != nil {
				old := renewJitter
				renewJitter = tc.jitter
				t.Cleanup(func() { renewJitter = old })
			}
			cert := &x509.Certificate{NotBefore: testNow, NotAfter: testNow.Add(tc.life)}
			if !tc.random {
				assert.Equal(t, tc.want, renewTime(cert).Sub(testNow))
				return
			}
			least, most := tc.life, time.Duration(0)
			for range 1000 {
				got := renewTime(cert).Sub(testNow)
				require.GreaterOrEqual(t, got, tc.life/2)
				require.Less(t, got, tc.life*5/6)
				least, most = min(least, got), max(most, got)
			}
			assert.Less(t, least, 13*time.Hour, "the times use the start of the range")
			assert.Greater(t, most, 19*time.Hour, "the times use the end of the range")
		})
	}
}

func TestSetRelays(t *testing.T) {
	ca := newTestCA(t, "ca")
	key := newKey(t)
	leaf := certPEM(ca.issue(t, &key.PublicKey, testID, testNow))
	cases := []struct {
		name     string
		roots    []byte
		wantPool bool
		wantErr  bool
	}{
		{name: "roots", roots: ca.pem, wantPool: true},
		{name: "no roots means the system roots"},
		{name: "roots are a leaf", roots: leaf, wantErr: true},
		{name: "roots are not PEM", roots: []byte("junk"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewCredential(key, leaf, ca.pem)
			require.NoError(t, err)
			err = c.SetRelays(testRelays, tc.roots)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Empty(t, c.Relays)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testRelays, c.Relays)
			assert.Equal(t, tc.wantPool, c.RelayPool() != nil)
		})
	}
}

func TestSaveLoadCredential(t *testing.T) {
	ca := newTestCA(t, "ca")
	path := filepath.Join(t.TempDir(), "agents", "laptop.json")

	_, err := LoadCredential(path)
	assert.ErrorIs(t, err, os.ErrNotExist)

	for i := range 2 {
		key := newKey(t)
		notBefore := testNow.Add(time.Duration(i) * time.Hour)
		renewAfter(t, 13*time.Hour)
		c, err := NewCredential(key, certPEM(ca.issue(t, &key.PublicKey, testID, notBefore)), ca.pem)
		require.NoError(t, err)
		// The second file has no relays and no roots.
		if i == 0 {
			require.NoError(t, c.SetRelays(testRelays, ca.pem))
		}
		require.NoError(t, SaveCredential(path, c))

		// The file does not have the renew time. Each load picks its own.
		renewAfter(t, 19*time.Hour)
		got, err := LoadCredential(path)
		require.NoError(t, err)
		assert.Equal(t, notBefore.Add(13*time.Hour), c.RenewAt())
		assert.Equal(t, notBefore.Add(19*time.Hour), got.RenewAt())
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var fields map[string]any
		require.NoError(t, json.Unmarshal(data, &fields))
		want := []string{"caBundle", "certificate", "key"}
		if i == 0 {
			want = append(want, "relayRoots", "relays")
		}
		assert.Equal(t, want, slices.Sorted(maps.Keys(fields)))
		assert.True(t, got.Key.Equal(c.Key))
		assert.Equal(t, c.Cert.Raw, got.Cert.Raw)
		assert.Equal(t, c.CABundle, got.CABundle)
		assert.Equal(t, c.Relays, got.Relays)
		assert.Equal(t, c.RelayRoots, got.RelayRoots)
		assert.Equal(t, i == 0, got.RelayPool() != nil)

		st, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}
	// Only the cache file stays; no temp files.
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}
