package controllers_test

import (
	"log"
	"os"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/controllers"
)

func TestTunnelReconciler(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogr(t))

	// Scheme
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	// Given a Tunnel without credentials
	tun := mkTunnel("tun-happy")

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}).
		WithObjects(tun).
		Build()

	r := controllers.NewTunnelReconciler(c)

	// When
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: tun.Name}})
	require.NoError(t, err)

	// Then
	var got corev1alpha2.Tunnel
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: tun.Name}, &got))

	// Finalizer added
	assert.True(t, controllerutil.ContainsFinalizer(&got, controllers.ApiServerFinalizer))

	// Token created in status
	require.NotNil(t, got.Status.Credentials)
	assert.NotEmpty(t, got.Status.Credentials.Token, "expected an opaque bearer token to be generated")
}

func testLogr(t *testing.T) logr.Logger {
	if testing.Verbose() {
		l := stdr.New(log.New(os.Stdout, "", log.LstdFlags))
		return l
	}
	return logr.Discard()
}

func mkTunnel(name string) *corev1alpha2.Tunnel {
	return &corev1alpha2.Tunnel{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Tunnel",
			APIVersion: "core.apoxy.dev/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}
