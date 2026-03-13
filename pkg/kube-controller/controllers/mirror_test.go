package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	apoxygatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	apoxyfake "github.com/apoxy-dev/apoxy/client/versioned/fake"
	"github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi"
)

func newTestReconciler(t *testing.T, localObjs []runtime.Object, apoxyObjs []runtime.Object, coordObjs []runtime.Object) *MirrorReconciler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, gwapiv1.Install(scheme))
	require.NoError(t, gwapiv1alpha2.Install(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, obj := range localObjs {
		builder = builder.WithRuntimeObjects(obj)
	}
	localClient := builder.Build()

	apoxyClient := apoxyfake.NewSimpleClientset(apoxyObjs...)
	kubeClient := kubernetesfake.NewSimpleClientset(coordObjs...)

	return NewMirrorReconciler(
		localClient,
		apoxyClient,
		kubeClient.CoordinationV1(),
		&configv1alpha1.KubeMirrorConfig{
			ClusterName: "test-cluster",
			Mirror:      configv1alpha1.MirrorModeGateway,
			Namespace:   "apoxy-system",
		},
	)
}

func apoxyGatewayClass() *gwapiv1.GatewayClass {
	return &gwapiv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "apoxy",
		},
		Spec: gwapiv1.GatewayClassSpec{
			ControllerName: gwapiv1.GatewayController(gatewayapi.StandaloneControllerName),
		},
	}
}

// --- mirrorName ---

func TestMirrorName(t *testing.T) {
	t.Parallel()
	r := newTestReconciler(t, nil, nil, nil)

	name := r.mirrorName("default", "my-gateway")
	assert.Contains(t, name, "my-gateway-")
	assert.Len(t, name, len("my-gateway-")+8) // 8 hex chars

	// Deterministic.
	assert.Equal(t, name, r.mirrorName("default", "my-gateway"))

	// Different namespace produces different suffix.
	assert.NotEqual(t, name, r.mirrorName("other-ns", "my-gateway"))
}

// --- originLabels ---

func TestOriginLabels(t *testing.T) {
	t.Parallel()
	r := newTestReconciler(t, nil, nil, nil)

	labels := r.originLabels("prod", "gw")
	assert.Equal(t, "test-cluster", labels[labelCluster])
	assert.Equal(t, "prod", labels[labelNamespace])
	assert.Equal(t, "gw", labels[labelName])
}

// --- heartbeatAnnotations ---

func TestHeartbeatAnnotations(t *testing.T) {
	t.Parallel()
	r := newTestReconciler(t, nil, nil, nil)

	before := time.Now().UTC()
	anns := r.heartbeatAnnotations()
	after := time.Now().UTC()

	ts, err := time.Parse(time.RFC3339, anns[annotationHeartbeat])
	require.NoError(t, err)
	assert.False(t, ts.Before(before.Truncate(time.Second)))
	assert.False(t, ts.After(after.Add(time.Second)))
}

// --- rewriteV1ParentRefs ---

func TestRewriteV1ParentRefs(t *testing.T) {
	t.Parallel()
	r := newTestReconciler(t, nil, nil, nil)

	ns := gwapiv1.Namespace("default")
	refs := []gwapiv1.ParentReference{
		{Name: "gw1", Namespace: &ns},
		{Name: "gw2"},
	}

	rewritten := r.rewriteV1ParentRefs("default", refs)
	require.Len(t, rewritten, 2)

	// Name should be rewritten to mirror name.
	assert.Equal(t, gwapiv1.ObjectName(r.mirrorName("default", "gw1")), rewritten[0].Name)
	assert.Equal(t, gwapiv1.ObjectName(r.mirrorName("default", "gw2")), rewritten[1].Name)

	// Namespace should be cleared (Apoxy resources are cluster-scoped).
	assert.Nil(t, rewritten[0].Namespace)
	assert.Nil(t, rewritten[1].Namespace)
}

// --- rewriteV1Alpha2ParentRefs ---

func TestRewriteV1Alpha2ParentRefs(t *testing.T) {
	t.Parallel()
	r := newTestReconciler(t, nil, nil, nil)

	ns := gwapiv1alpha2.Namespace("kube-system")
	refs := []gwapiv1alpha2.ParentReference{
		{Name: "tcp-gw", Namespace: &ns},
	}

	rewritten := r.rewriteV1Alpha2ParentRefs("kube-system", refs)
	require.Len(t, rewritten, 1)
	assert.Equal(t, gwapiv1alpha2.ObjectName(r.mirrorName("kube-system", "tcp-gw")), rewritten[0].Name)
	assert.Nil(t, rewritten[0].Namespace)
}

// --- syncGateway ---

func TestSyncGateway_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := newTestReconciler(t, nil, nil, nil)

	gw := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-gw",
			Namespace: "default",
		},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "apoxy",
			Listeners: []gwapiv1.Listener{{
				Name:     "http",
				Port:     8080,
				Protocol: gwapiv1.HTTPProtocolType,
			}},
		},
	}

	result, err := r.syncGateway(ctx, gw)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	apoxyName := r.mirrorName("default", "my-gw")
	created, err := r.apoxyClient.GatewayV1().Gateways().Get(ctx, apoxyName, metav1.GetOptions{})
	require.NoError(t, err)

	// Labels.
	assert.Equal(t, "test-cluster", created.Labels[labelCluster])
	assert.Equal(t, "default", created.Labels[labelNamespace])
	assert.Equal(t, "my-gw", created.Labels[labelName])

	// Heartbeat annotation.
	_, hasHeartbeat := created.Annotations[annotationHeartbeat]
	assert.True(t, hasHeartbeat)

	// Spec preserved.
	assert.Equal(t, gwapiv1.ObjectName("apoxy"), created.Spec.GatewayClassName)
	require.Len(t, created.Spec.Listeners, 1)
	assert.Equal(t, gwapiv1.PortNumber(8080), created.Spec.Listeners[0].Port)
}

func TestSyncGateway_Update(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	apoxyName := (&MirrorReconciler{clusterName: "test-cluster"}).mirrorName("default", "my-gw")
	existing := &apoxygatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:   apoxyName,
			Labels: map[string]string{labelCluster: "test-cluster"},
		},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "apoxy",
			Listeners: []gwapiv1.Listener{{
				Name:     "http",
				Port:     8080,
				Protocol: gwapiv1.HTTPProtocolType,
			}},
		},
	}

	r := newTestReconciler(t, nil, []runtime.Object{existing}, nil)

	gw := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-gw",
			Namespace: "default",
		},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "apoxy",
			Listeners: []gwapiv1.Listener{{
				Name:     "https",
				Port:     8443,
				Protocol: gwapiv1.HTTPSProtocolType,
			}},
		},
	}

	result, err := r.syncGateway(ctx, gw)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	updated, err := r.apoxyClient.GatewayV1().Gateways().Get(ctx, apoxyName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, updated.Spec.Listeners, 1)
	assert.Equal(t, gwapiv1.PortNumber(8443), updated.Spec.Listeners[0].Port)
	assert.Equal(t, gwapiv1.HTTPSProtocolType, updated.Spec.Listeners[0].Protocol)
}

// --- syncHTTPRoute ---

func TestSyncHTTPRoute_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := newTestReconciler(t, nil, nil, nil)

	ns := gwapiv1.Namespace("default")
	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-route",
			Namespace: "default",
		},
		Spec: gwapiv1.HTTPRouteSpec{
			CommonRouteSpec: gwapiv1.CommonRouteSpec{
				ParentRefs: []gwapiv1.ParentReference{{
					Name:      "my-gw",
					Namespace: &ns,
				}},
			},
		},
	}

	result, err := r.syncHTTPRoute(ctx, route)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	apoxyName := r.mirrorName("default", "my-route")
	created, err := r.apoxyClient.GatewayV1().HTTPRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	require.NoError(t, err)

	// Labels.
	assert.Equal(t, "test-cluster", created.Labels[labelCluster])

	// Heartbeat annotation.
	_, hasHeartbeat := created.Annotations[annotationHeartbeat]
	assert.True(t, hasHeartbeat)

	// Parent refs rewritten.
	require.Len(t, created.Spec.ParentRefs, 1)
	assert.Equal(t, gwapiv1.ObjectName(r.mirrorName("default", "my-gw")), created.Spec.ParentRefs[0].Name)
	assert.Nil(t, created.Spec.ParentRefs[0].Namespace)
}

// --- syncTCPRoute ---

func TestSyncTCPRoute_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := newTestReconciler(t, nil, nil, nil)

	ns := gwapiv1alpha2.Namespace("default")
	route := &gwapiv1alpha2.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tcp-route",
			Namespace: "default",
		},
		Spec: gwapiv1alpha2.TCPRouteSpec{
			CommonRouteSpec: gwapiv1alpha2.CommonRouteSpec{
				ParentRefs: []gwapiv1alpha2.ParentReference{{
					Name:      "my-gw",
					Namespace: &ns,
				}},
			},
		},
	}

	result, err := r.syncTCPRoute(ctx, route)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	apoxyName := r.mirrorName("default", "tcp-route")
	created, err := r.apoxyClient.GatewayV1alpha2().TCPRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	require.NoError(t, err)

	assert.Equal(t, "test-cluster", created.Labels[labelCluster])
	_, hasHeartbeat := created.Annotations[annotationHeartbeat]
	assert.True(t, hasHeartbeat)
	require.Len(t, created.Spec.ParentRefs, 1)
	assert.Nil(t, created.Spec.ParentRefs[0].Namespace)
}

// --- delete ---

func TestDeleteApoxyGateway(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	apoxyName := (&MirrorReconciler{clusterName: "test-cluster"}).mirrorName("default", "my-gw")
	existing := &apoxygatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: apoxyName,
		},
	}

	r := newTestReconciler(t, nil, []runtime.Object{existing}, nil)

	// Delete existing.
	result, err := r.deleteApoxyGateway(ctx, apoxyName)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	_, err = r.apoxyClient.GatewayV1().Gateways().Get(ctx, apoxyName, metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err))

	// Delete non-existent is a no-op.
	result, err = r.deleteApoxyGateway(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestDeleteApoxyHTTPRoute(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	apoxyName := (&MirrorReconciler{clusterName: "test-cluster"}).mirrorName("default", "my-route")
	existing := &apoxygatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name: apoxyName,
		},
	}

	r := newTestReconciler(t, nil, []runtime.Object{existing}, nil)

	result, err := r.deleteApoxyHTTPRoute(ctx, apoxyName)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	_, err = r.apoxyClient.GatewayV1().HTTPRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err))
}

// --- reconcileGateway (full round-trip) ---

func TestReconcileGateway_CreatesMirror(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	gwc := apoxyGatewayClass()
	gw := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-gw",
			Namespace: "default",
		},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "apoxy",
			Listeners: []gwapiv1.Listener{{
				Name:     "http",
				Port:     80,
				Protocol: gwapiv1.HTTPProtocolType,
			}},
		},
	}

	r := newTestReconciler(t, []runtime.Object{gwc, gw}, nil, nil)

	result, err := r.reconcileGateway(ctx, reconcile.Request{
		NamespacedName: nn("default", "my-gw"),
	})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	apoxyName := r.mirrorName("default", "my-gw")
	created, err := r.apoxyClient.GatewayV1().Gateways().Get(ctx, apoxyName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "test-cluster", created.Labels[labelCluster])
}

func TestReconcileGateway_IgnoresNonApoxy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	gwc := &gwapiv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "other"},
		Spec:       gwapiv1.GatewayClassSpec{ControllerName: "other.io/controller"},
	}
	gw := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-gw",
			Namespace: "default",
		},
		Spec: gwapiv1.GatewaySpec{GatewayClassName: "other"},
	}

	r := newTestReconciler(t, []runtime.Object{gwc, gw}, nil, nil)

	result, err := r.reconcileGateway(ctx, reconcile.Request{
		NamespacedName: nn("default", "other-gw"),
	})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Should not have created anything.
	apoxyName := r.mirrorName("default", "other-gw")
	_, err = r.apoxyClient.GatewayV1().Gateways().Get(ctx, apoxyName, metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err))
}

func TestReconcileGateway_DeletesOnNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	apoxyName := (&MirrorReconciler{clusterName: "test-cluster"}).mirrorName("default", "deleted-gw")
	existing := &apoxygatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: apoxyName},
	}

	r := newTestReconciler(t, nil, []runtime.Object{existing}, nil)

	// Gateway no longer exists locally.
	result, err := r.reconcileGateway(ctx, reconcile.Request{
		NamespacedName: nn("default", "deleted-gw"),
	})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	_, err = r.apoxyClient.GatewayV1().Gateways().Get(ctx, apoxyName, metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err))
}

// --- reconcileHTTPRoute (full round-trip) ---

func TestReconcileHTTPRoute_CreatesMirror(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	gwc := apoxyGatewayClass()
	gw := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gw", Namespace: "default"},
		Spec:       gwapiv1.GatewaySpec{GatewayClassName: "apoxy"},
	}
	ns := gwapiv1.Namespace("default")
	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "default"},
		Spec: gwapiv1.HTTPRouteSpec{
			CommonRouteSpec: gwapiv1.CommonRouteSpec{
				ParentRefs: []gwapiv1.ParentReference{{
					Name: "my-gw", Namespace: &ns,
				}},
			},
		},
	}

	r := newTestReconciler(t, []runtime.Object{gwc, gw, route}, nil, nil)

	result, err := r.reconcileHTTPRoute(ctx, reconcile.Request{
		NamespacedName: nn("default", "my-route"),
	})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	apoxyName := r.mirrorName("default", "my-route")
	created, err := r.apoxyClient.GatewayV1().HTTPRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "test-cluster", created.Labels[labelCluster])
	require.Len(t, created.Spec.ParentRefs, 1)
	assert.Nil(t, created.Spec.ParentRefs[0].Namespace)
}

// --- renewLease ---

func TestRenewLease_CreatesNew(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := newTestReconciler(t, nil, nil, nil)

	err := r.renewLease(ctx, "apoxy-system", "mirror-test-cluster", 30)
	require.NoError(t, err)

	lease, err := r.coordinationClient.Leases("apoxy-system").Get(ctx, "mirror-test-cluster", metav1.GetOptions{})
	require.NoError(t, err)

	assert.Equal(t, "test-cluster", *lease.Spec.HolderIdentity)
	assert.Equal(t, int32(30), *lease.Spec.LeaseDurationSeconds)
	assert.NotNil(t, lease.Spec.AcquireTime)
	assert.NotNil(t, lease.Spec.RenewTime)
}

func TestRenewLease_RenewsExisting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	oldTime := metav1.NewMicroTime(time.Now().Add(-20 * time.Second))
	existingLease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mirror-test-cluster",
			Namespace: "apoxy-system",
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptr.To("test-cluster"),
			LeaseDurationSeconds: ptr.To(int32(30)),
			AcquireTime:          &oldTime,
			RenewTime:            &oldTime,
		},
	}

	r := newTestReconciler(t, nil, nil, []runtime.Object{existingLease})

	before := time.Now()
	err := r.renewLease(ctx, "apoxy-system", "mirror-test-cluster", 30)
	require.NoError(t, err)

	lease, err := r.coordinationClient.Leases("apoxy-system").Get(ctx, "mirror-test-cluster", metav1.GetOptions{})
	require.NoError(t, err)

	// RenewTime should be updated to approximately now.
	assert.True(t, lease.Spec.RenewTime.Time.After(before.Add(-time.Second)))
	assert.Equal(t, "test-cluster", *lease.Spec.HolderIdentity)
}

// --- reconcileTCPRoute (v1alpha2 round-trip) ---

func TestReconcileTCPRoute_CreatesMirror(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	gwc := apoxyGatewayClass()
	gw := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "tcp-gw", Namespace: "default"},
		Spec:       gwapiv1.GatewaySpec{GatewayClassName: "apoxy"},
	}
	ns := gwapiv1alpha2.Namespace("default")
	route := &gwapiv1alpha2.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "tcp-route", Namespace: "default"},
		Spec: gwapiv1alpha2.TCPRouteSpec{
			CommonRouteSpec: gwapiv1alpha2.CommonRouteSpec{
				ParentRefs: []gwapiv1alpha2.ParentReference{{
					Name: "tcp-gw", Namespace: &ns,
				}},
			},
		},
	}

	r := newTestReconciler(t, []runtime.Object{gwc, gw, route}, nil, nil)

	result, err := r.reconcileTCPRoute(ctx, reconcile.Request{
		NamespacedName: nn("default", "tcp-route"),
	})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	apoxyName := r.mirrorName("default", "tcp-route")
	created, err := r.apoxyClient.GatewayV1alpha2().TCPRoutes().Get(ctx, apoxyName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "test-cluster", created.Labels[labelCluster])
}

// --- helpers ---

func nn(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}
