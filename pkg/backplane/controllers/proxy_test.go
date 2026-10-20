package controllers

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

const fakeEnvoyStartsEnv = "PROXY_TEST_FAKE_ENVOY_STARTS"

// TestMain doubles as a fake Envoy that runs until SIGTERM.
func TestMain(m *testing.M) {
	if p := os.Getenv(fakeEnvoyStartsEnv); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			f.WriteString("start\n")
			f.Close()
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM)
		<-sig
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestReconcileAfterSIGTERMNeverStartsEnvoy(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))
	p := &corev1alpha2.Proxy{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy"},
		Spec: corev1alpha2.ProxySpec{
			Shutdown: &corev1alpha2.ShutdownConfig{
				DrainTimeout:     &metav1.Duration{Duration: time.Second},
				MinimumDrainTime: &metav1.Duration{},
			},
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(p).
		WithStatusSubresource(&corev1alpha2.Proxy{}).
		Build()
	r := NewProxyReconciler(c, "proxy", "replica", netip.MustParseAddr("10.0.0.1"), "")

	// SIGTERM before the first generation exists.
	stopped, done := r.Runtime.BeginShutdownBy(time.Now().Add(time.Second))
	<-stopped
	<-done
	for i := 0; i < 2; i++ {
		res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "proxy"}})
		require.NoError(t, err)
		assert.Zero(t, res.RequeueAfter)
		assert.False(t, res.Requeue)
	}
	ps := r.RuntimeStatus()
	assert.False(t, ps.Starting)
	assert.False(t, ps.Running)
	assert.True(t, ps.StartedAt.IsZero())
}

func TestReconcileDeletionDuringRestart(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))
	key := types.NamespacedName{Name: "proxy"}
	p := &corev1alpha2.Proxy{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy", Finalizers: []string{"test/hold"}},
		Spec: corev1alpha2.ProxySpec{
			Shutdown: &corev1alpha2.ShutdownConfig{
				DrainTimeout:     &metav1.Duration{Duration: 100 * time.Millisecond},
				MinimumDrainTime: &metav1.Duration{},
			},
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(p).
		WithStatusSubresource(&corev1alpha2.Proxy{}).
		Build()
	r := NewProxyReconciler(c, "proxy", "replica", netip.MustParseAddr("10.0.0.1"), "")
	r.Runtime.EnvoyPath = os.Args[0]
	starts := filepath.Join(t.TempDir(), "starts")
	t.Setenv(fakeEnvoyStartsEnv, starts)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	t.Cleanup(func() { r.Runtime.KillEnvoy() })
	startCount := func() int {
		b, _ := os.ReadFile(starts)
		return bytes.Count(b, []byte("start\n"))
	}
	ctx := context.Background()
	reconcileOnce := func() {
		t.Helper()
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		require.NoError(t, err)
	}

	reconcileOnce() // Starts Envoy.
	require.Eventually(t, func() bool { return r.RuntimeStatus().Running && startCount() == 1 }, 5*time.Second, 5*time.Millisecond)

	// Crash: the supervisor waits 1s before the restart.
	require.NoError(t, r.Runtime.KillEnvoy())
	require.Eventually(t, func() bool { return !r.RuntimeStatus().Running }, 5*time.Second, 5*time.Millisecond)
	got := &corev1alpha2.Proxy{}
	require.NoError(t, c.Get(ctx, key, got))
	require.NoError(t, c.Delete(ctx, got))
	reconcileOnce()

	time.Sleep(1500 * time.Millisecond)
	assert.Equal(t, 1, startCount(), "no restart after the deletion")
	assert.False(t, r.RuntimeStatus().Running)
}
