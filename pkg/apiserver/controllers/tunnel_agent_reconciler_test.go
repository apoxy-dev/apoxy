package controllers_test

import (
	"context"
	"log"
	"net/netip"
	"os"
	"testing"
	"time"

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
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/controllers"
	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

func newFakeClient(t *testing.T, scheme *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	b := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&corev1alpha2.TunnelAgent{})
	if len(objs) > 0 {
		b = b.WithObjects(objs...)
	}
	return b.Build()
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

func mkTunnel(name string, uid types.UID) *corev1alpha2.Tunnel {
	return &corev1alpha2.Tunnel{
		TypeMeta:   metav1.TypeMeta{Kind: "Tunnel", APIVersion: "core.apoxy.dev/v1alpha2"},
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: uid},
	}
}

func getAgent(t *testing.T, ctx context.Context, client client.Client, name string) *corev1alpha2.TunnelAgent {
	t.Helper()
	var out corev1alpha2.TunnelAgent
	require.NoError(t, client.Get(ctx, types.NamespacedName{Name: name}, &out))
	return &out
}

func testLogger(t *testing.T) logr.Logger {
	if testing.Verbose() {
		// stdr adapts the standard library logger to logr
		l := stdr.New(log.New(os.Stdout, "", log.LstdFlags))
		return l
	}
	return logr.Discard()
}

func TestTunnelAgentReconciler(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogger(t))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	systemULA := tunnet.NewULA(ctx, tunnet.SystemNetworkID)
	// Agent prefixes are /96 subnets that can embed IPv4 suffixes.
	agentIPAM, err := systemULA.IPAM(ctx, 96)
	require.NoError(t, err)

	agent := mkAgent("ta-happy", "tun-1")
	tunnel := mkTunnel("tun-1", "uid-1")

	client := newFakeClient(t, scheme, agent, tunnel)

	tokenRefreshThreshold := 3 * time.Minute
	privKey, pubKey, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	r, err := controllers.NewTunnelAgentReconciler(client, privKey, pubKey, tokenRefreshThreshold, agentIPAM)
	require.NoError(t, err)

	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: agent.Name}})
	require.NoError(t, err)

	agent = getAgent(t, ctx, client, agent.Name)

	assert.True(t, controllerutil.ContainsFinalizer(agent, controllers.ApiServerFinalizer))
	require.Len(t, agent.OwnerReferences, 1)
	require.NotNil(t, agent.OwnerReferences[0].Controller)
	assert.True(t, *agent.OwnerReferences[0].Controller)

	assert.NotEmpty(t, agent.Status.Prefix, "prefix should be allocated")
	require.NotNil(t, agent.Status.Credentials)
	assert.NotEmpty(t, agent.Status.Credentials.Token, "token should be issued")

	min := time.Duration(float64(tokenRefreshThreshold) * 0.9)
	max := time.Duration(float64(tokenRefreshThreshold) * 1.1)
	assert.Truef(t, res.RequeueAfter >= min && res.RequeueAfter <= max,
		"requeue after ~threshold with jitter; got %v, expected in [%v,%v]", res.RequeueAfter, min, max)
}

func TestTunnelAgentReconciler_RefreshLifecycle(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogger(t))

	// Scheme & CRDs
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	// IPAM (/96 prefixes under system ULA for agents)
	systemULA := tunnet.NewULA(ctx, tunnet.SystemNetworkID)
	agentIPAM, err := systemULA.IPAM(ctx, 96)
	require.NoError(t, err)

	// Test resources & reconciler
	ta := mkAgent("ta-refresh", "tun-r")
	tun := mkTunnel("tun-r", "uid-r")
	c := newFakeClient(t, scheme, ta, tun)

	privKey, pubKey, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	tokenRefreshThreshold := 5 * time.Minute
	r, err := controllers.NewTunnelAgentReconciler(c, privKey, pubKey, tokenRefreshThreshold, agentIPAM)
	require.NoError(t, err)

	// Prime to fully provisioned: finalizer, ownerRef, prefix, initial token.
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: ta.Name}})
	require.NoError(t, err)

	issuer, err := token.NewIssuer(privKey)
	require.NoError(t, err)

	t.Run("long-lived token schedules at exp - threshold", func(t *testing.T) {
		cur := getAgent(t, ctx, c, ta.Name)

		// 30m token -> expect requeue at (exp - thr) with jitter
		tok, claims, err := issuer.IssueToken(cur.Name, 30*time.Minute)
		require.NoError(t, err)
		exp, err := claims.GetExpirationTime()
		require.NoError(t, err)

		upd := cur.DeepCopy()
		if upd.Status.Credentials == nil {
			upd.Status.Credentials = &corev1alpha2.TunnelCredentials{}
		}
		upd.Status.Credentials.Token = tok
		require.NoError(t, c.Status().Update(ctx, upd))

		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: ta.Name}})
		require.NoError(t, err)

		want := time.Until(exp.Time.Add(-tokenRefreshThreshold))
		min := time.Duration(float64(want) * 0.9)
		max := time.Duration(float64(want) * 1.1)
		assert.Truef(t, res.RequeueAfter >= 0, "non-negative RequeueAfter")
		assert.Truef(t, res.RequeueAfter >= min && res.RequeueAfter <= max,
			"got %v want in [%v,%v]", res.RequeueAfter, min, max)
	})

	t.Run("near-expiry token gets reissued and schedules ~threshold", func(t *testing.T) {
		cur := getAgent(t, ctx, c, ta.Name)

		// < threshold token -> should be reissued and schedule ~thr
		nearTok, _, err := issuer.IssueToken(cur.Name, 2*time.Minute)
		require.NoError(t, err)

		upd := cur.DeepCopy()
		upd.Status.Credentials.Token = nearTok
		require.NoError(t, c.Status().Update(ctx, upd))

		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: ta.Name}})
		require.NoError(t, err)

		cur = getAgent(t, ctx, c, ta.Name)
		require.NotNil(t, cur.Status.Credentials)
		assert.NotEqual(t, nearTok, cur.Status.Credentials.Token, "expected a freshly issued token")

		minThr := time.Duration(float64(tokenRefreshThreshold) * 0.9)
		maxThr := time.Duration(float64(tokenRefreshThreshold) * 1.1)
		assert.Truef(t, res.RequeueAfter >= minThr && res.RequeueAfter <= maxThr,
			"got %v want in [%v,%v]", res.RequeueAfter, minThr, maxThr)
	})
}

func TestTunnelAgentReconciler_MissingTunnel(t *testing.T) {
	ctx := ctrl.LoggerInto(t.Context(), testLogger(t))

	// Scheme & CRDs
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	// IPAM (/96 prefixes under system ULA for agents)
	systemULA := tunnet.NewULA(ctx, tunnet.SystemNetworkID)
	agentIPAM, err := systemULA.IPAM(ctx, 96)
	require.NoError(t, err)

	// Start with an agent that references a tunnel that doesn't exist yet.
	ta := mkAgent("ta-wait", "tun-wait")
	c := newFakeClient(t, scheme, ta)

	// Reconciler
	privKey, pubKey, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)
	tokenRefreshThreshold := 3 * time.Minute

	r, err := controllers.NewTunnelAgentReconciler(c, privKey, pubKey, tokenRefreshThreshold, agentIPAM)
	require.NoError(t, err)

	// 1) Missing Tunnel -> expect ~10s RequeueAfter
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: ta.Name}})
	require.NoError(t, err)
	assert.InDelta(t, float64(10*time.Second), float64(res.RequeueAfter), float64(time.Second))

	// Sanity: finalizer should already be ensured even while waiting.
	got := getAgent(t, ctx, c, ta.Name)
	assert.True(t, controllerutil.ContainsFinalizer(got, controllers.ApiServerFinalizer))

	// 2) Create the Tunnel -> next reconcile should fully provision the agent.
	require.NoError(t, c.Create(ctx, mkTunnel("tun-wait", "uid-wait")))

	res, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: ta.Name}})
	require.NoError(t, err)

	got = getAgent(t, ctx, c, ta.Name)

	// OwnerRef set (controller=true)
	require.Len(t, got.OwnerReferences, 1)
	require.NotNil(t, got.OwnerReferences[0].Controller)
	assert.True(t, *got.OwnerReferences[0].Controller)

	// Prefix allocated & token issued
	assert.NotEmpty(t, got.Status.Prefix, "prefix should be allocated")
	require.NotNil(t, got.Status.Credentials)
	assert.NotEmpty(t, got.Status.Credentials.Token, "token should be issued")

	// Next requeue should be around the refresh threshold (with jitter).
	min := time.Duration(float64(tokenRefreshThreshold) * 0.9)
	max := time.Duration(float64(tokenRefreshThreshold) * 1.1)
	assert.Truef(t, res.RequeueAfter >= min && res.RequeueAfter <= max,
		"requeue after ~threshold with jitter; got %v, expected in [%v,%v]", res.RequeueAfter, min, max)
}

func TestTunnelAgentReconciler_DeletionAndCleanup(t *testing.T) {
	ctx := ctrl.LoggerInto(context.Background(), logr.Discard())

	// Scheme & CRDs
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(scheme))

	// Agent marked for deletion, with finalizer and prefix.
	ta := mkAgent("ta-del", "tun-d")
	controllerutil.AddFinalizer(ta, controllers.ApiServerFinalizer)
	ta.Status.Prefix = "fd00:dead:beef::/96"
	now := metav1.Now()
	ta.DeletionTimestamp = &now

	c := newFakeClient(t, scheme, ta)

	// Mock IPAM: expect Release called once with correct prefix
	agentIPAM := &mockIPAM{}
	pfx := netip.MustParsePrefix(ta.Status.Prefix)
	agentIPAM.On("Release", pfx).Return(nil).Once()

	// Reconciler
	privKey, pubKey, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)
	r, err := controllers.NewTunnelAgentReconciler(c, privKey, pubKey, time.Minute, agentIPAM)
	require.NoError(t, err)

	// Act
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: ta.Name}})
	require.NoError(t, err)

	// Assert: after removing the last finalizer on a resource with DeletionTimestamp set,
	// the object should be fully deleted by the API server (and the fake client mirrors that).
	var gone corev1alpha2.TunnelAgent
	err = c.Get(ctx, types.NamespacedName{Name: ta.Name}, &gone)
	require.Error(t, err, "object should be deleted once finalizer is removed")
	assert.True(t, apierrors.IsNotFound(err), "expected NotFound after deletion")

	agentIPAM.AssertExpectations(t)
}

type mockIPAM struct {
	mock.Mock
}

func (m *mockIPAM) Allocate() (netip.Prefix, error) {
	args := m.Called()
	return args.Get(0).(netip.Prefix), args.Error(1)
}

func (m *mockIPAM) Release(p netip.Prefix) error {
	args := m.Called(p)
	return args.Error(0)
}
