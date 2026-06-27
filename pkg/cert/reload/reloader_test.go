package reload

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReloader_GetCertificate(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, _, _ := makeCertPEM(t)
	dir := t.TempDir()
	writeKeyPairDir(t, dir, certPEM, keyPEM)

	r, err := NewReloader(FromDir(dir), "test")
	require.NoError(t, err)

	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	require.NotEmpty(t, got.Certificate)
	require.NotNil(t, got.Leaf)
}

func TestReloader_HotReloadViaRotation(t *testing.T) {
	certV1, keyV1, fpV1, _ := makeCertPEM(t)
	certV2, keyV2, fpV2, _ := makeCertPEM(t)
	require.NotEqual(t, fpV1, fpV2)

	proj := newKubeletProjection(t, certV1, keyV1)
	r, err := NewReloader(FromDir(proj.root), "test")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Start(ctx) }()

	v1, err := r.GetCertificate(nil)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	// Rotate by rewriting the files — the reload must be driven by the real
	// on-disk change, not by any test-forced timestamp poke.
	proj.write(t, certV2, keyV2)

	require.Eventually(t, func() bool {
		got, gerr := r.GetCertificate(nil)
		return gerr == nil && !bytes.Equal(got.Certificate[0], v1.Certificate[0])
	}, 3*time.Second, 25*time.Millisecond, "GetCertificate never returned the rotated cert")
}

func TestNewReloader_MissingCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := NewReloader(FromDir(dir), "test")
	require.Error(t, err, "constructor must fail when the cert is absent")
}

func TestNewReloader_RetriesPastTornWrite(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, _, _ := makeCertPEM(t)

	// Land a valid keypair shortly after construction begins — within the
	// startup retry window — to simulate a (re)start that races an
	// in-progress rotation.
	go func() {
		time.Sleep(2 * startupLoadDelay)
		writeKeyPairDir(t, dir, certPEM, keyPEM)
	}()

	r, err := NewReloader(FromDir(dir), "test")
	require.NoError(t, err, "constructor should tolerate a brief torn-write window")
	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	require.NotEmpty(t, got.Certificate)
}

func TestReloader_GetCertificateBeforeLoad(t *testing.T) {
	t.Parallel()
	// A Reloader whose store was never seeded surfaces ErrNoCertificate
	// rather than panicking on a nil bundle.
	r := &Reloader{store: NewStore(), paths: FromDir(t.TempDir())}
	_, err := r.GetCertificate(nil)
	require.ErrorIs(t, err, ErrNoCertificate)
}

func TestFromDir(t *testing.T) {
	t.Parallel()
	p := FromDir("/etc/apoxy/certs")
	require.Equal(t, filepath.Join("/etc/apoxy/certs", "tls.crt"), p.Cert)
	require.Equal(t, filepath.Join("/etc/apoxy/certs", "tls.key"), p.Key)
	require.Equal(t, filepath.Join("/etc/apoxy/certs", "ca.crt"), p.CA)
}
