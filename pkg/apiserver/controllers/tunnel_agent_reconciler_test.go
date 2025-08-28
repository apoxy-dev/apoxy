package controllers_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/controllers"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

func TestTunnelAgentReconciler(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	// Scheme
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	systemULA := tunnet.NewULA(ctx, tunnet.SystemNetworkID)
	// Agent prefixes are /96 subnets that can embed IPv4 suffixes.
	agentIPAM, err := systemULA.IPAM(ctx, 96)
	require.NoError(t, err)

	// Given a TunnelAgent referencing a Tunnel
	tun := mkTunnel("tun-happy")
	agent := mkAgent("agent-happy", "tun-happy")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}, &corev1alpha2.TunnelAgent{}).
		WithObjects(tun, agent).
		Build()

	r := controllers.NewTunnelAgentReconciler(c, agentIPAM)

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

	// IP assigned in status
	require.NotEmpty(t, got.Status.Prefix)
}

func mkAgent(name, tunnelName string) *corev1alpha2.TunnelAgent {
	return &corev1alpha2.TunnelAgent{
		TypeMeta: metav1.TypeMeta{Kind: "TunnelAgent", APIVersion: "core.apoxy.dev/v1alpha2"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1alpha2.TunnelAgentSpec{
			TunnelRef: corev1alpha2.TunnelRef{Name: tunnelName},
		},
	}
}
