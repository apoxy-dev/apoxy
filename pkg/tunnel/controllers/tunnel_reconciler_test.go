package controllers_test

import (
	"net/netip"
	"testing"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

func TestTunnelReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	tunnel := &corev1alpha2.Tunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "tun-1"},
		Status: corev1alpha2.TunnelStatus{
			Credentials: &corev1alpha2.TunnelCredentials{Token: "secret-token"},
		},
	}

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}).
		WithObjects(tunnel).
		Build()

	relay := &mockRelay{}
	relay.On("SetCredentials", "secret-token").Once()

	r := controllers.NewTunnelReconciler(c, relay, "")

	_, err := r.Reconcile(ctrl.LoggerInto(t.Context(), testLogr(t)),
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "tun-1"}})
	require.NoError(t, err)

	relay.AssertExpectations(t)
}

type mockRelay struct {
	mock.Mock
}

func (m *mockRelay) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockRelay) Address() netip.AddrPort {
	args := m.Called()
	return args.Get(0).(netip.AddrPort)
}

func (m *mockRelay) SetCredentials(token string) {
	m.Called(token)
}
