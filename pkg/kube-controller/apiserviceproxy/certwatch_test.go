package apiserviceproxy

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// kubeletProjection lays out a tmp dir the way kubelet does for a mounted
// Secret: a timestamped data dir holds the actual files, and ..data is a
// symlink to it. Rotating points the symlink at a new data dir.
type kubeletProjection struct {
	root string
	gen  int
}

func newKubeletProjection(t *testing.T, certPEM, keyPEM []byte) *kubeletProjection {
	t.Helper()
	p := &kubeletProjection{root: t.TempDir()}
	p.write(t, certPEM, keyPEM)
	return p
}

func (p *kubeletProjection) write(t *testing.T, certPEM, keyPEM []byte) {
	t.Helper()
	p.gen++
	gendir := filepath.Join(p.root, "..gen"+itoa(p.gen))
	require.NoError(t, os.Mkdir(gendir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gendir, "tls.crt"), certPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(gendir, "tls.key"), keyPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(gendir, "ca.crt"), nil, 0o400))

	// Re-point ..data via atomic rename. Mirrors kubelet's behavior — a
	// single rename(2) takes the parent dir from generation N to N+1.
	tmpLink := filepath.Join(p.root, "..data.tmp")
	_ = os.Remove(tmpLink)
	require.NoError(t, os.Symlink(gendir, tmpLink))
	require.NoError(t, os.Rename(tmpLink, filepath.Join(p.root, "..data")))

	// Materialize the projected files at the top level via symlinks. The
	// kubelet does this for each key in the Secret, pointing at ..data.
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
		target := filepath.Join(p.root, name)
		_ = os.Remove(target)
		require.NoError(t, os.Symlink(filepath.Join("..data", name), target))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestCertWatcher_PicksUpRotation(t *testing.T) {
	certV1, keyV1, fpV1, _ := makeClientCertPEM(t)
	certV2, keyV2, fpV2, expV2 := makeClientCertPEM(t)
	require.NotEqual(t, fpV1, fpV2, "test certs must differ")

	proj := newKubeletProjection(t, certV1, keyV1)
	store := newCertStore()

	// Seed the store the same way configureCloudProxy does.
	boot, err := loadBundleFromDisk(proj.root)
	require.NoError(t, err)
	store.Store(boot)
	require.Equal(t, fpV1, store.Load().fp)

	var swapped atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runCertWatcher(ctx, proj.root, store, func(*certBundle) {
			swapped.Add(1)
		})
	}()

	// Give the watcher a moment to wire up before we rotate.
	time.Sleep(50 * time.Millisecond)
	proj.write(t, certV2, keyV2)

	require.Eventually(t, func() bool {
		return store.Load().fp == fpV2
	}, 3*time.Second, 25*time.Millisecond, "watcher never picked up v2")
	require.True(t, store.Load().notAfter.Equal(expV2))
	require.Equal(t, int32(1), swapped.Load(), "onSwap fired exactly once")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not exit on ctx cancel")
	}
}

func TestCertWatcher_IgnoresMissingDir(t *testing.T) {
	store := newCertStore()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// Non-existent dir — should return nil immediately (hot-reload
	// disabled, pod stays up).
	err := runCertWatcher(ctx, filepath.Join(t.TempDir(), "does-not-exist"), store, nil)
	require.NoError(t, err)
}

func TestCertWatcher_IgnoresEmptyDir(t *testing.T) {
	store := newCertStore()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// Empty dir flag — pre-mount-rollout deployments call configureCloudProxy
	// without WithCertDir. Should be a no-op.
	err := runCertWatcher(ctx, "", store, nil)
	require.NoError(t, err)
}
