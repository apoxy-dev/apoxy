package reload

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// kubeletProjection lays out a tmp dir the way kubelet does for a mounted
// Secret: a timestamped data dir holds the actual files, and ..data is a
// symlink to it. Rotating points the symlink at a new data dir — the same
// atomic swap a real cert-manager renewal produces.
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
	gendir := filepath.Join(p.root, "..gen"+strconv.Itoa(p.gen))
	require.NoError(t, os.Mkdir(gendir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gendir, SecretCertFile), certPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(gendir, SecretKeyFile), keyPEM, 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(gendir, SecretCAFile), nil, 0o400))

	tmpLink := filepath.Join(p.root, "..data.tmp")
	_ = os.Remove(tmpLink)
	require.NoError(t, os.Symlink(gendir, tmpLink))
	require.NoError(t, os.Rename(tmpLink, filepath.Join(p.root, "..data")))

	for _, name := range []string{SecretCertFile, SecretKeyFile, SecretCAFile} {
		target := filepath.Join(p.root, name)
		_ = os.Remove(target)
		require.NoError(t, os.Symlink(filepath.Join("..data", name), target))
	}
}

func TestWatch_PicksUpRotation(t *testing.T) {
	certV1, keyV1, fpV1, _ := makeCertPEM(t)
	certV2, keyV2, fpV2, expV2 := makeCertPEM(t)
	require.NotEqual(t, fpV1, fpV2, "test certs must differ")

	proj := newKubeletProjection(t, certV1, keyV1)
	store := NewStore()

	// Seed the store the way NewReloader does.
	boot, err := LoadBundle(FromDir(proj.root))
	require.NoError(t, err)
	store.Store(boot)
	require.Equal(t, fpV1, store.Load().Fingerprint)

	var swapped atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Watch(ctx, FromDir(proj.root), store, WatchOptions{
			OnSwap: func(*Bundle) { swapped.Add(1) },
		})
	}()

	// Give the watcher a moment to wire up before we rotate.
	time.Sleep(50 * time.Millisecond)
	proj.write(t, certV2, keyV2)

	require.Eventually(t, func() bool {
		return store.Load().Fingerprint == fpV2
	}, 3*time.Second, 25*time.Millisecond, "watcher never picked up v2")
	require.True(t, store.Load().NotAfter.Equal(expV2))
	require.Equal(t, int32(1), swapped.Load(), "onSwap fired exactly once")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not exit on ctx cancel")
	}
}

func TestWatch_IgnoresMissingDir(t *testing.T) {
	store := NewStore()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// Parent dir doesn't exist — Watch returns nil (hot-reload disabled,
	// process stays up).
	err := Watch(ctx, FromDir(filepath.Join(t.TempDir(), "does-not-exist")), store, WatchOptions{})
	require.NoError(t, err)
}
