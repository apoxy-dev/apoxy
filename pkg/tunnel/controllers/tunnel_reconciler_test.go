package controllers_test

import (
	"context"
	"log"
	"net/netip"
	"os"
	"testing"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
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
	relay.On("Address").Return(netip.MustParseAddrPort("1.1.1.1:443"))
	relay.On("SetCredentials", "tun-1", "secret-token").Once()
	relay.On("SetRelayAddresses", "tun-1", mock.Anything).Once()
	relay.On("SetEgressGateway", mock.Anything).Return().Once()
	relay.On("SetOnShutdown", mock.Anything).Return().Once()

	r := controllers.NewTunnelReconciler(c, relay, "")

	_, err := r.Reconcile(ctrl.LoggerInto(t.Context(), testLogr(t)),
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "tun-1"}})
	require.NoError(t, err)

	relay.AssertExpectations(t)
}

func TestTunnelReconciler_OnShutdownRemovesAddress(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	relayAddr := netip.MustParseAddrPort("1.1.1.1:443")

	tunnel := &corev1alpha2.Tunnel{
		ObjectMeta: metav1.ObjectMeta{Name: "tun-1"},
		Status: corev1alpha2.TunnelStatus{
			// Seed with our relay address plus another one to ensure only ours is removed.
			Addresses: []string{relayAddr.String(), "2.2.2.2:443"},
		},
	}

	c := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1alpha2.Tunnel{}).
		WithObjects(tunnel).
		Build()

	relay := &mockRelay{}
	relay.On("Address").Return(relayAddr)

	var onShutdown func()
	relay.
		On("SetOnShutdown", mock.Anything).
		Run(func(args mock.Arguments) {
			onShutdown = args.Get(0).(func())
		}).
		Return().
		Once()

	// We don't need other relay expectations for this test.
	controllers.NewTunnelReconciler(c, relay, "")

	// Sanity: ensure the tunnel initially contains the relay address.
	var before corev1alpha2.Tunnel
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "tun-1"}, &before))
	require.Contains(t, before.Status.Addresses, relayAddr.String())

	// Invoke the captured shutdown hook.
	require.NotNil(t, onShutdown, "onShutdown should be captured from SetOnShutdown")
	onShutdown()

	// After shutdown, our relay address should be removed from the status.
	var after corev1alpha2.Tunnel
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "tun-1"}, &after))
	require.NotContains(t, after.Status.Addresses, relayAddr.String())
	require.ElementsMatch(t, []string{"2.2.2.2:443"}, after.Status.Addresses)

	relay.AssertExpectations(t)
}

func testLogr(t *testing.T) logr.Logger {
	if testing.Verbose() {
		l := stdr.New(log.New(os.Stdout, "", log.LstdFlags))
		return l
	}
	return logr.Discard()
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

func (m *mockRelay) SetCredentials(tunnelName, token string) {
	m.Called(tunnelName, token)
}

func (m *mockRelay) SetRelayAddresses(tunnelName string, addresses []string) {
	m.Called(tunnelName, addresses)
}

func (m *mockRelay) SetEgressGateway(enabled bool) {
	m.Called(enabled)
}

func (m *mockRelay) SetOnConnect(onConnect func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error) {
	m.Called(onConnect)
}

func (m *mockRelay) SetOnDisconnect(onDisconnect func(ctx context.Context, agentName, id string) error) {
	m.Called(onDisconnect)
}

func (m *mockRelay) SetOnShutdown(onShutdown func()) {
	m.Called(onShutdown)
}
