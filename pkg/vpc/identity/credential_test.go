package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCredential(t *testing.T) {
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
		c, err := NewCredential(key, certPEM(ca.issue(t, &key.PublicKey, testID, testNow.Add(time.Duration(i)*time.Hour))), ca.pem)
		require.NoError(t, err)
		// The second file has no relays and no roots.
		if i == 0 {
			require.NoError(t, c.SetRelays(testRelays, ca.pem))
		}
		require.NoError(t, SaveCredential(path, c))

		got, err := LoadCredential(path)
		require.NoError(t, err)
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
