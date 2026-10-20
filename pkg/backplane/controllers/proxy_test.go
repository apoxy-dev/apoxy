package controllers

import (
	"bytes"
	"context"
	"log/slog"
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

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/backplane/envoy"
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

func TestReplicaDeletion(t *testing.T) {
	rs := &ctrlv1alpha1.ProxyReplicaStatus{Phase: ctrlv1alpha1.ProxyReplicaPhaseRunning}

	assert.Equal(t, terminatingRequeue, replicaDeletion(slog.Default(), false, envoy.RuntimeStatus{Running: true}, rs))
	assert.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseTerminating, rs.Phase)

	// The Terminating status write is the last watch event; only the requeue
	// sees the supervisor exit.
	assert.Equal(t, terminatingRequeue, replicaDeletion(slog.Default(), false, envoy.RuntimeStatus{Running: true}, rs))

	rs.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
	assert.Equal(t, terminatingRequeue, replicaDeletion(slog.Default(), false, envoy.RuntimeStatus{}, rs),
		"between a crash and the restart the supervisor still runs")
	assert.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseTerminating, rs.Phase)

	assert.Zero(t, replicaDeletion(slog.Default(), true, envoy.RuntimeStatus{}, rs))
	assert.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseStopped, rs.Phase)
}

func TestReconcileDeletionCompletes(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, ctrlv1alpha1.Install(scheme))
	now := metav1.NewTime(time.Now())
	p := &ctrlv1alpha1.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "proxy",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test/hold"},
		},
		Status: ctrlv1alpha1.ProxyStatus{
			Replicas: []*ctrlv1alpha1.ProxyReplicaStatus{{
				Name:  "replica",
				Phase: ctrlv1alpha1.ProxyReplicaPhaseTerminating,
			}},
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(p).
		WithStatusSubresource(&ctrlv1alpha1.Proxy{}).
		Build()
	r := NewProxyReconciler(c, "proxy", "replica", netip.MustParseAddr("10.0.0.1"), "")

	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "proxy"}})
	require.NoError(t, err)
	assert.Zero(t, res.RequeueAfter)

	got := &ctrlv1alpha1.Proxy{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "proxy"}, got))
	rs, ok := findReplicaStatus(got, "replica")
	require.True(t, ok)
	assert.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseStopped, rs.Phase)
}

func TestReconcileAfterSIGTERMNeverStartsEnvoy(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, ctrlv1alpha1.Install(scheme))
	p := &ctrlv1alpha1.Proxy{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy"},
		Spec: ctrlv1alpha1.ProxySpec{
			DrainTimeout:     &metav1.Duration{Duration: time.Second},
			MinimumDrainTime: &metav1.Duration{},
		},
		Status: ctrlv1alpha1.ProxyStatus{
			Replicas: []*ctrlv1alpha1.ProxyReplicaStatus{{
				Name:  "replica",
				Phase: ctrlv1alpha1.ProxyReplicaPhasePending,
			}},
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(p).
		WithStatusSubresource(&ctrlv1alpha1.Proxy{}).
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

func TestReconcileCrashRecoveryThenDeletion(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, ctrlv1alpha1.Install(scheme))
	key := types.NamespacedName{Name: "proxy"}
	p := &ctrlv1alpha1.Proxy{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy", Finalizers: []string{"test/hold"}},
		Spec: ctrlv1alpha1.ProxySpec{
			DrainTimeout:     &metav1.Duration{Duration: 100 * time.Millisecond},
			MinimumDrainTime: &metav1.Duration{},
		},
		Status: ctrlv1alpha1.ProxyStatus{
			Replicas: []*ctrlv1alpha1.ProxyReplicaStatus{{
				Name:  "replica",
				Phase: ctrlv1alpha1.ProxyReplicaPhasePending,
			}},
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(p).
		WithStatusSubresource(&ctrlv1alpha1.Proxy{}).
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
	reconcileOnce := func() reconcile.Result {
		t.Helper()
		res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		require.NoError(t, err)
		return res
	}
	phase := func() ctrlv1alpha1.ProxyReplicaPhase {
		t.Helper()
		got := &ctrlv1alpha1.Proxy{}
		require.NoError(t, c.Get(ctx, key, got))
		rs, ok := findReplicaStatus(got, "replica")
		require.True(t, ok)
		return rs.Phase
	}

	reconcileOnce() // Starts Envoy.
	require.Eventually(t, func() bool { return r.RuntimeStatus().Running && startCount() == 1 }, 5*time.Second, 5*time.Millisecond)
	reconcileOnce()
	require.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseRunning, phase())

	// Crash: a reconcile in the restart window marks the replica Failed.
	require.NoError(t, r.Runtime.KillEnvoy())
	require.Eventually(t, func() bool { return r.RuntimeStatus().Running && startCount() == 2 }, 5*time.Second, 5*time.Millisecond)
	got := &ctrlv1alpha1.Proxy{}
	require.NoError(t, c.Get(ctx, key, got))
	rs, _ := findReplicaStatus(got, "replica")
	rs.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
	require.NoError(t, c.Status().Update(ctx, got))

	reconcileOnce()
	assert.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseRunning, phase(), "the supervisor recovered Envoy")

	require.NoError(t, c.Delete(ctx, got))
	res := reconcileOnce()
	assert.Equal(t, terminatingRequeue, res.RequeueAfter)
	assert.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseTerminating, phase())
	require.Eventually(t, func() bool { return !r.RuntimeStatus().Running }, 10*time.Second, 10*time.Millisecond, "the deletion shuts Envoy down")
	res = reconcileOnce()
	assert.Zero(t, res.RequeueAfter)
	assert.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseStopped, phase())
	assert.Equal(t, 2, startCount())
}

func TestReconcileDeletionDuringRestart(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, ctrlv1alpha1.Install(scheme))
	key := types.NamespacedName{Name: "proxy"}
	p := &ctrlv1alpha1.Proxy{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy", Finalizers: []string{"test/hold"}},
		Spec: ctrlv1alpha1.ProxySpec{
			DrainTimeout:     &metav1.Duration{Duration: 100 * time.Millisecond},
			MinimumDrainTime: &metav1.Duration{},
		},
		Status: ctrlv1alpha1.ProxyStatus{
			Replicas: []*ctrlv1alpha1.ProxyReplicaStatus{{
				Name:  "replica",
				Phase: ctrlv1alpha1.ProxyReplicaPhasePending,
			}},
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(p).
		WithStatusSubresource(&ctrlv1alpha1.Proxy{}).
		Build()
	r := NewProxyReconciler(c, "proxy", "replica", netip.MustParseAddr("10.0.0.1"), "")
	// A wrapper whose exec fails while it is not executable holds the
	// supervisor between a crash and a successful restart.
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "envoy")
	require.NoError(t, os.WriteFile(wrapper, []byte("#!/bin/sh\nexec "+os.Args[0]+" \"$@\"\n"), 0o755))
	r.Runtime.EnvoyPath = wrapper
	starts := filepath.Join(dir, "starts")
	t.Setenv(fakeEnvoyStartsEnv, starts)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	t.Cleanup(func() { r.Runtime.KillEnvoy() })
	startCount := func() int {
		b, _ := os.ReadFile(starts)
		return bytes.Count(b, []byte("start\n"))
	}
	ctx := context.Background()
	reconcileOnce := func() reconcile.Result {
		t.Helper()
		res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		require.NoError(t, err)
		return res
	}
	phase := func() ctrlv1alpha1.ProxyReplicaPhase {
		t.Helper()
		got := &ctrlv1alpha1.Proxy{}
		require.NoError(t, c.Get(ctx, key, got))
		rs, ok := findReplicaStatus(got, "replica")
		require.True(t, ok)
		return rs.Phase
	}

	reconcileOnce() // Starts Envoy.
	require.Eventually(t, func() bool { return r.RuntimeStatus().Running && startCount() == 1 }, 5*time.Second, 5*time.Millisecond)
	reconcileOnce()
	require.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseRunning, phase())

	require.NoError(t, os.Chmod(wrapper, 0o644))
	require.NoError(t, r.Runtime.KillEnvoy())
	require.Eventually(t, func() bool { return !r.RuntimeStatus().Running }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // The supervisor fails to restart Envoy.

	got := &ctrlv1alpha1.Proxy{}
	require.NoError(t, c.Get(ctx, key, got))
	require.NoError(t, c.Delete(ctx, got))
	deadline := time.Now().Add(10 * time.Second)
	res := reconcileOnce()
	for res.RequeueAfter > 0 {
		require.True(t, time.Now().Before(deadline), "deletion never completed")
		require.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseTerminating, phase())
		time.Sleep(10 * time.Millisecond)
		res = reconcileOnce()
	}
	require.Equal(t, ctrlv1alpha1.ProxyReplicaPhaseStopped, phase())
	assert.True(t, isClosed(r.Runtime.BeginStop()), "Stopped only once the supervisor exited")

	// The binary works again; a live supervisor would restart Envoy now.
	require.NoError(t, os.Chmod(wrapper, 0o755))
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, 1, startCount())
	assert.False(t, r.RuntimeStatus().Running)
}
