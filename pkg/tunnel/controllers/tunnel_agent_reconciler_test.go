package controllers_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
)

func TestTunnelAgentReconciler_AddConnection(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	tunnel := mkTunnel("tunnel-1")

	agent := mkAgent("tunnel-1", "agent-1")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(tunnel, agent).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-a")
	relay.On("Address").Return(netip.MustParseAddrPort("203.0.113.10:443"))
	relay.On("SetOnConnect", mock.Anything).Return().Once()
	relay.On("SetOnDisconnect", mock.Anything).Return().Once()

	r := controllers.NewTunnelAgentReconciler(c, relay, "")

	conn := &mockConn{}
	conn.On("ID").Return("conn-123")

	require.NoError(t, r.AddConnection(ctx, tunnel.Name, agent.Name, conn))

	var got corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got))

	require.Len(t, got.Status.Connections, 1)
	entry := got.Status.Connections[0]
	assert.Equal(t, "conn-123", entry.ID)
	// Address and VNI should NOT be set by AddConnection (populated by the apiserver reconciler).
	assert.Equal(t, "", entry.Address)
	assert.Nil(t, entry.VNI)
	assert.Equal(t, relay.Address().String(), entry.RelayAddress)

	finalizer := "tunnelrelay.apoxy.dev/" + relay.Name() + "-finalizer"
	assert.True(t, controllerutil.ContainsFinalizer(&got, finalizer))

	conn.AssertExpectations(t)
	relay.AssertExpectations(t)
}

func TestTunnelAgentReconciler_RemoveConnection(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	tunnel := mkTunnel("tunnel-1")

	agent := mkAgent("tunnel-1", "agent-2")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(tunnel, agent).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-a")
	relay.On("Address").Return(netip.MustParseAddrPort("203.0.113.20:443"))
	relay.On("SetOnConnect", mock.Anything).Return().Once()
	relay.On("SetOnDisconnect", mock.Anything).Return().Once()

	r := controllers.NewTunnelAgentReconciler(c, relay, "")
	finalizer := "tunnelrelay.apoxy.dev/" + relay.Name() + "-finalizer"

	// Two mock conns
	conn1 := &mockConn{}
	conn1.On("ID").Return("c1").Maybe()
	conn1.On("Close").Return(nil).Once()

	conn2 := &mockConn{}
	conn2.On("ID").Return("c2").Maybe()
	conn2.On("Close").Return(nil).Once()

	require.NoError(t, r.AddConnection(ctx, tunnel.Name, agent.Name, conn1))
	require.NoError(t, r.AddConnection(ctx, tunnel.Name, agent.Name, conn2))

	// Remove first
	require.NoError(t, r.RemoveConnection(ctx, agent.Name, "c1"))
	var got corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got))
	assert.Len(t, got.Status.Connections, 1)
	assert.True(t, controllerutil.ContainsFinalizer(&got, finalizer))

	// Remove second — the CR should be deleted now that no connections remain
	require.NoError(t, r.RemoveConnection(ctx, agent.Name, "c2"))
	err := c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got)
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err))

	relay.AssertExpectations(t)
}

func TestTunnelAgentReconciler_ClosesConnections(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	tunnel := mkTunnel("tunnel-1")

	agent := mkAgent("tunnel-1", "agent-3")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(tunnel, agent).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-z")
	relay.On("Address").Return(netip.MustParseAddrPort("198.51.100.7:8443"))
	relay.On("SetOnConnect", mock.Anything).Return().Once()
	relay.On("SetOnDisconnect", mock.Anything).Return().Once()

	r := controllers.NewTunnelAgentReconciler(c, relay, "")
	finalizer := "tunnelrelay.apoxy.dev/" + relay.Name() + "-finalizer"

	// Mock conn that should be closed
	conn := &mockConn{}
	conn.On("ID").Return("close-me").Maybe()
	conn.On("Close").Return(nil).Once()

	// Add connection -> status + in-memory tracking + finalizer
	require.NoError(t, r.AddConnection(ctx, tunnel.Name, agent.Name, conn))

	// Ensure finalizer exists before deletion
	var cur corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &cur))
	require.True(t, controllerutil.ContainsFinalizer(&cur, finalizer), "expected finalizer before deletion")

	// Simulate deletion properly: client.Delete sets deletionTimestamp (object sticks around due to finalizer)
	require.NoError(t, c.Delete(ctx, &cur))

	// Reconcile deletion (should close conn, drop from map, and remove finalizer)
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: agent.Name}})
	require.NoError(t, err)

	// After reconcile, object may be fully gone already (OK) or still present sans finalizer.
	var after corev1alpha2.TunnelAgent
	err = c.Get(ctx, types.NamespacedName{Name: agent.Name}, &after)
	if !apierrors.IsNotFound(err) {
		require.NoError(t, err)
		assert.False(t, controllerutil.ContainsFinalizer(&after, finalizer), "finalizer should be removed on deletion")
	}

	// Ensure Close() was called
	conn.AssertExpectations(t)
	relay.AssertExpectations(t)
}

func TestTunnelAgentReconcile_SetsAddressAndVNI(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	tunnel := mkTunnel("tunnel-1")

	agent := mkAgent("tunnel-1", "agent-4")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(tunnel, agent).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-x")
	relay.On("Address").Return(netip.MustParseAddrPort("192.0.2.77:7443"))
	relay.On("SetOnConnect", mock.Anything).Return().Once()
	relay.On("SetOnDisconnect", mock.Anything).Return().Once()

	r := controllers.NewTunnelAgentReconciler(c, relay, "")

	// Create a live connection tracked by the reconciler.
	conn := &mockConn{}
	conn.On("ID").Return("live-1")

	require.NoError(t, r.AddConnection(ctx, tunnel.Name, agent.Name, conn))

	// Simulate the apiserver reconciler filling status.address & vni
	var cur corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &cur))
	require.Len(t, cur.Status.Connections, 1)
	cur.Status.Connections[0].Address = "10.123.0.5/32"
	v := uint(4242)
	cur.Status.Connections[0].VNI = &v
	require.NoError(t, c.Status().Update(ctx, &cur))

	// Expect our live connection to receive SetOverlayAddress + SetVNI on reconcile
	conn.On("SetOverlayAddress", "10.123.0.5/32").Return(nil).Once()
	conn.On("SetVNI", mock.Anything, uint(4242)).Return(nil).Once()

	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: agent.Name}})
	require.NoError(t, err)

	conn.AssertExpectations(t)
	relay.AssertExpectations(t)
}

func TestTunnelAgentPushStatsOnce_UpdatesStatusForKnownConnection(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	tunnel := mkTunnel("tun-stats")
	agent := mkAgent("tun-stats", "agent-stats")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(tunnel, agent).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-stats")
	relay.On("Address").Return(netip.MustParseAddrPort("203.0.113.30:443"))
	relay.On("SetOnConnect", mock.Anything).Return().Once()
	relay.On("SetOnDisconnect", mock.Anything).Return().Once()

	r := controllers.NewTunnelAgentReconciler(c, relay, "")

	conn := &mockConn{}
	conn.On("ID").Return("conn-stat").Maybe()

	require.NoError(t, r.AddConnection(ctx, tunnel.Name, agent.Name, conn))

	lastRX := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	conn.On("Stats").Return(controllers.ConnectionStats{
		RXBytes: 1111,
		TXBytes: 2222,
		LastRX:  lastRX,
	}, true).Once()

	r.PushStatsOnce(ctx)

	var got corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got))
	require.Len(t, got.Status.Connections, 1)
	entry := got.Status.Connections[0]
	assert.Equal(t, "conn-stat", entry.ID)
	assert.Equal(t, int64(2222), *entry.RXBytes) // From the agent's perspective
	assert.Equal(t, int64(1111), *entry.TXBytes)
	require.NotNil(t, entry.LastRX)
	assert.True(t, entry.LastRX.Time.Equal(lastRX))

	relay.AssertExpectations(t)
	conn.AssertExpectations(t)
}

func mkTunnel(tunnelName string) *corev1alpha2.Tunnel {
	return &corev1alpha2.Tunnel{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Tunnel",
			APIVersion: "core.apoxy.dev/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: tunnelName,
		},
	}
}

func mkAgent(tunnelName, agentName string) *corev1alpha2.TunnelAgent {
	return &corev1alpha2.TunnelAgent{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TunnelAgent",
			APIVersion: "core.apoxy.dev/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: agentName,
		},
		Spec: corev1alpha2.TunnelAgentSpec{
			TunnelRef: corev1alpha2.TunnelRef{
				Name: tunnelName,
			},
		},
	}
}

type mockConn struct {
	mock.Mock
}

func (m *mockConn) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockConn) SetOverlayAddress(addr string) error {
	args := m.Called(addr)
	return args.Error(0)
}

func (m *mockConn) SetVNI(ctx context.Context, v uint) error {
	args := m.Called(ctx, v)
	return args.Error(0)
}

func (m *mockConn) Stats() (controllers.ConnectionStats, bool) {
	args := m.Called()
	return args.Get(0).(controllers.ConnectionStats), args.Bool(1)
}

func (m *mockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}
