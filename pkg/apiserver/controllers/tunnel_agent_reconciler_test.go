package controllers_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/controllers"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

func TestTunnelAgentReconciler(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	// Scheme
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	systemULA := tunnet.NewULA(ctx, tunnet.SystemNetworkID)
	// Agent allocations are still prefixes (e.g., /96)
	agentIPAM, err := systemULA.IPAM(ctx, 96)
	require.NoError(t, err)

	// Given: a Tunnel and a TunnelAgent with one connection missing Address
	tun := mkTunnel("tun-happy")
	agent := mkAgentWithEmptyConnection("agent-happy", "tun-happy")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(tun, agent).
		Build()

	r := controllers.NewTunnelAgentReconciler(c, agentIPAM, vni.NewVNIPool())

	// When
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: agent.Name}})
	require.NoError(t, err)

	// Then
	var got corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got))

	// Finalizer added
	require.True(t, controllerutil.ContainsFinalizer(&got, controllers.ApiServerFinalizer))

	// Owner reference to parent Tunnel
	require.Len(t, got.OwnerReferences, 1)
	require.Equal(t, tun.Name, got.OwnerReferences[0].Name)

	// Address assigned in status for the connection that was empty
	require.Len(t, got.Status.Connections, 1)
	require.NotEmpty(t, got.Status.Connections[0].Address, "expected Address to be set on the connection")

	if pfx, err := netip.ParsePrefix(got.Status.Connections[0].Address); err == nil {
		require.True(t, pfx.IsValid(), "allocated overlay prefix should be valid")
	} else {
		t.Fatalf("allocated Address is not a valid prefix: %v", err)
	}

	// VNI assigned in status for the connection that was empty
	require.NotNil(t, got.Status.Connections[0].VNI, "expected VNI to be set on the connection")
	require.Equal(t, *got.Status.Connections[0].VNI, uint(1))
}

func TestTunnelAgentReconciler_DeletionReleasesResourcesAndRemovesFinalizer(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	// Scheme
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	// IPAM + VNI pool
	systemULA := tunnet.NewULA(ctx, tunnet.SystemNetworkID)
	agentIPAM, err := systemULA.IPAM(ctx, 96)
	require.NoError(t, err)

	vpool := vni.NewVNIPool()

	// Pre-allocate a prefix and VNI that we'll pretend belong to the agent
	pfx, err := agentIPAM.Allocate()
	require.NoError(t, err)
	v, err := vpool.Allocate()
	require.NoError(t, err)
	require.Equal(t, uint(1), v, "sanity check VNI allocation order")

	// Agent marked for deletion, with finalizer and those resources in status
	agent := &corev1alpha2.TunnelAgent{
		TypeMeta: metav1.TypeMeta{Kind: "TunnelAgent", APIVersion: "core.apoxy.dev/v1alpha2"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "agent-deleting",
			Finalizers:        []string{controllers.ApiServerFinalizer},
			DeletionTimestamp: &metav1.Time{Time: metav1.Now().Time},
		},
		Spec: corev1alpha2.TunnelAgentSpec{
			TunnelRef: corev1alpha2.TunnelRef{Name: "tun-any"},
		},
		Status: corev1alpha2.TunnelAgentStatus{
			Connections: []corev1alpha2.TunnelAgentConnection{
				{
					ID:           "conn-1",
					RelayAddress: "relay-1",
					Address:      pfx.String(),
					VNI:          &v,
				},
			},
		},
	}

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(agent).
		Build()

	r := controllers.NewTunnelAgentReconciler(c, agentIPAM, vpool)

	// When: reconcile deletion
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: agent.Name}})
	require.NoError(t, err)

	// Then: the object should be fully deleted by the API server once the finalizer is removed
	var got corev1alpha2.TunnelAgent
	err = c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got)
	require.Error(t, err)
	require.True(t, apierrors.IsNotFound(err), "expected agent to be deleted after finalizer removal")

	// And: resources were released back to their pools (same prefix/VNI available again)
	rePfx, err := agentIPAM.Allocate()
	require.NoError(t, err)
	require.Equal(t, pfx, rePfx, "expected released prefix to be available again")

	reV, err := vpool.Allocate()
	require.NoError(t, err)
	require.Equal(t, uint(1), reV, "expected released VNI to be available again")
}

func TestTunnelAgentPruneOrphanedConnections(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	// Scheme
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	// IPAM + VNI pool
	systemULA := tunnet.NewULA(ctx, tunnet.SystemNetworkID)
	agentIPAM, err := systemULA.IPAM(ctx, 96)
	require.NoError(t, err)

	vpool := vni.NewVNIPool()

	// Allocate resources we'll assign to connections
	pfxOrphaned, err := agentIPAM.Allocate()
	require.NoError(t, err)
	vOrphaned, err := vpool.Allocate()
	require.NoError(t, err)
	require.Equal(t, uint(1), vOrphaned)

	pfxFresh, err := agentIPAM.Allocate()
	require.NoError(t, err)
	vFresh, err := vpool.Allocate()
	require.NoError(t, err)
	require.Equal(t, uint(2), vFresh)

	// Times must be metav1.Time, not time.Time
	now := time.Now().UTC()
	orphaned := metav1.Time{Time: now.Add(-1 * time.Hour)} // orphaned -> should be pruned
	fresh := metav1.Time{Time: now.Add(-1 * time.Minute)}  // fresh -> should stay

	agent := &corev1alpha2.TunnelAgent{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TunnelAgent",
			APIVersion: "core.apoxy.dev/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "agent-gc",
		},
		Spec: corev1alpha2.TunnelAgentSpec{
			TunnelRef: corev1alpha2.TunnelRef{Name: "tun-any"},
		},
		Status: corev1alpha2.TunnelAgentStatus{
			Connections: []corev1alpha2.TunnelAgentConnection{
				{
					ID:              "conn-orphaned",
					Address:         pfxOrphaned.String(),
					VNI:             &vOrphaned,
					LastRXTimestamp: &orphaned,
				},
				{
					ID:              "conn-fresh",
					Address:         pfxFresh.String(),
					VNI:             &vFresh,
					LastRXTimestamp: &fresh,
				},
			},
		},
	}

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(agent).
		Build()

	r := controllers.NewTunnelAgentReconciler(c, agentIPAM, vpool)

	// WHEN GC runs
	require.NoError(t, r.PruneOrphanedConnections(ctx))

	// THEN orphan pruned, fresh kept
	var got corev1alpha2.TunnelAgent
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: agent.Name}, &got))
	require.Len(t, got.Status.Connections, 1)
	require.Equal(t, "conn-fresh", got.Status.Connections[0].ID)

	// Released resources are available again
	rePfx, err := agentIPAM.Allocate()
	require.NoError(t, err)
	require.Equal(t, pfxOrphaned, rePfx)

	reV, err := vpool.Allocate()
	require.NoError(t, err)
	require.Equal(t, vOrphaned, reV)
}

func mkAgentWithEmptyConnection(name, tunnelName string) *corev1alpha2.TunnelAgent {
	return &corev1alpha2.TunnelAgent{
		TypeMeta: metav1.TypeMeta{Kind: "TunnelAgent", APIVersion: "core.apoxy.dev/v1alpha2"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1alpha2.TunnelAgentSpec{
			TunnelRef: corev1alpha2.TunnelRef{Name: tunnelName},
		},
		Status: corev1alpha2.TunnelAgentStatus{
			Connections: []corev1alpha2.TunnelAgentConnection{
				{
					ID:           "conn-1",
					RelayAddress: "relay-1",
				},
			},
		},
	}
}
