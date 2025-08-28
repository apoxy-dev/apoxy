package controllers_test

import (
	"log"
	"net/netip"
	"os"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
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

func TestAddConnection_UpsertsStatusAndAddsFinalizer(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	agent := mkAgent("agent-1")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.TunnelAgent{}).
		WithObjects(agent).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-a")
	relay.On("Address").Return(netip.MustParseAddrPort("203.0.113.10:443"))

	r := controllers.NewTunnelAgentReconciler(c, relay, "")

	conn := &mockConn{}
	conn.On("ID").Return("conn-123")
	conn.On("Address").Return(netip.MustParsePrefix("10.0.0.1/32"))
	conn.On("VNI").Return(42)

	require.NoError(t, r.AddConnection(ctx, agent.Name, conn))

	var got corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got))

	require.Len(t, got.Status.Connections, 1)
	entry := got.Status.Connections[0]
	assert.Equal(t, "conn-123", entry.ID)
	assert.Equal(t, "10.0.0.1/32", entry.Address)
	assert.Equal(t, relay.Address().String(), entry.RelayAddress)
	assert.EqualValues(t, 42, entry.VNI)

	finalizer := "tunnelrelay.apoxy.dev/" + relay.Name() + "/finalizer"
	assert.True(t, controllerutil.ContainsFinalizer(&got, finalizer))

	conn.AssertExpectations(t)
}

func TestRemoveConnection_RemovesStatusAndFinalizerOnlyWhenNoRelayConnsRemain(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	agent := mkAgent("agent-2")
	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.TunnelAgent{}).
		WithObjects(agent).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-a")
	relay.On("Address").Return(netip.MustParseAddrPort("203.0.113.20:443"))
	r := controllers.NewTunnelAgentReconciler(c, relay, "")
	finalizer := "tunnelrelay.apoxy.dev/" + relay.Name() + "/finalizer"

	// Two mock conns
	conn1 := &mockConn{}
	conn1.On("ID").Return("c1").Maybe()
	conn1.On("Address").Return(netip.MustParsePrefix("10.0.0.1/32")).Maybe()
	conn1.On("VNI").Return(1).Maybe()

	conn2 := &mockConn{}
	conn2.On("ID").Return("c2").Maybe()
	conn2.On("Address").Return(netip.MustParsePrefix("10.0.0.2/32")).Maybe()
	conn2.On("VNI").Return(2).Maybe()

	require.NoError(t, r.AddConnection(ctx, agent.Name, conn1))
	require.NoError(t, r.AddConnection(ctx, agent.Name, conn2))

	// Remove first
	require.NoError(t, r.RemoveConnection(ctx, agent.Name, "c1"))
	var got corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got))
	assert.Len(t, got.Status.Connections, 1)
	assert.True(t, controllerutil.ContainsFinalizer(&got, finalizer))

	// Remove second
	require.NoError(t, r.RemoveConnection(ctx, agent.Name, "c2"))
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got))
	assert.Empty(t, got.Status.Connections)
	assert.False(t, controllerutil.ContainsFinalizer(&got, finalizer))
}

func TestReconcile_OnDeletion_ClosesConnectionsAndRemovesFinalizer(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	agent := mkAgent("agent-3")
	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.TunnelAgent{}).
		WithObjects(agent).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-z")
	relay.On("Address").Return(netip.MustParseAddrPort("198.51.100.7:8443"))
	r := controllers.NewTunnelAgentReconciler(c, relay, "")
	finalizer := "tunnelrelay.apoxy.dev/" + relay.Name() + "/finalizer"

	// Mock conn that should be closed
	conn := &mockConn{}
	conn.On("ID").Return("close-me").Maybe()
	conn.On("Address").Return(netip.MustParsePrefix("10.9.0.9/32")).Maybe()
	conn.On("VNI").Return(900).Maybe()
	conn.On("Close").Return(nil).Once()

	// Add connection -> status + in-memory tracking + finalizer
	require.NoError(t, r.AddConnection(ctx, agent.Name, conn))

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
	if apierrors.IsNotFound(err) {
		// Deleted is fine: finalizer must have been removed, allowing GC.
		err = nil
	} else {
		require.NoError(t, err)
		assert.False(t, controllerutil.ContainsFinalizer(&after, finalizer), "finalizer should be removed on deletion")
	}

	// Ensure Close() was called
	conn.AssertExpectations(t)
}

func TestReconcile_NotFound_NoError(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.TunnelAgent{}).
		Build()

	relay := &mockRelay{}
	relay.On("Name").Return("relay-n")
	relay.On("Address").Return(netip.MustParseAddrPort("203.0.113.55:443"))
	r := controllers.NewTunnelAgentReconciler(c, relay, "")

	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "does-not-exist"}})
	require.NoError(t, err)
}

func testLogr(t *testing.T) logr.Logger {
	if testing.Verbose() {
		l := stdr.New(log.New(os.Stdout, "", log.LstdFlags))
		return l
	}
	return logr.Discard()
}

func mkAgent(name string) *corev1alpha2.TunnelAgent {
	return &corev1alpha2.TunnelAgent{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TunnelAgent",
			APIVersion: "core.apoxy.dev/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
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

func (m *mockConn) Address() netip.Prefix {
	args := m.Called()
	return args.Get(0).(netip.Prefix)
}

func (m *mockConn) VNI() uint32 {
	args := m.Called()
	return uint32(args.Int(0))
}

func (m *mockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}
