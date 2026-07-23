package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

func newVPCNetworkReconciler(t *testing.T, objs ...client.Object) (*VPCNetworkReconciler, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(watcherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.VPCNetwork{}).
		WithObjects(objs...).
		Build()
	return NewVPCNetworkReconciler(c), c
}

func netReq(name string) reconcile.Request {
	return reconcile.Request{NamespacedName: client.ObjectKey{Name: name}}
}

func TestVPCNetworkReconcilerProvisions(t *testing.T) {
	ctx := context.Background()
	r, c := newVPCNetworkReconciler(t, &vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}})

	_, err := r.Reconcile(ctx, netReq("corp"))
	require.NoError(t, err)

	var got vpcv1alpha1.VPCNetwork
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "corp"}, &got))
	require.NotEmpty(t, got.Status.OverlayCIDR, "overlay /72 assigned")
	require.NotNil(t, got.Status.Credentials)
	require.NotEmpty(t, got.Status.Credentials.Token, "connect credential minted")
	require.NotNil(t, meta.FindStatusCondition(got.Status.Conditions, "Ready"))

	id, err := tunnet.NetworkIDFromCIDR(got.Status.OverlayCIDR)
	require.NoError(t, err)
	require.NotEqual(t, [3]byte{}, [3]byte(id), "system network id 0 is reserved")
}

func TestVPCNetworkReconcilerIsIdempotent(t *testing.T) {
	ctx := context.Background()
	r, c := newVPCNetworkReconciler(t, &vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}})

	_, err := r.Reconcile(ctx, netReq("corp"))
	require.NoError(t, err)
	var first vpcv1alpha1.VPCNetwork
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "corp"}, &first))

	_, err = r.Reconcile(ctx, netReq("corp"))
	require.NoError(t, err)
	var second vpcv1alpha1.VPCNetwork
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "corp"}, &second))

	require.Equal(t, first.Status.OverlayCIDR, second.Status.OverlayCIDR, "overlay is write-once")
	require.Equal(t, first.Status.Credentials.Token, second.Status.Credentials.Token, "credential is not re-minted")
}

func TestVPCNetworkReconcilerAssignsDistinctIDs(t *testing.T) {
	ctx := context.Background()
	r, c := newVPCNetworkReconciler(t,
		&vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
		&vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "b"}},
	)

	_, err := r.Reconcile(ctx, netReq("a"))
	require.NoError(t, err)
	_, err = r.Reconcile(ctx, netReq("b"))
	require.NoError(t, err)

	var a, b vpcv1alpha1.VPCNetwork
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "a"}, &a))
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "b"}, &b))
	require.NotEqual(t, a.Status.OverlayCIDR, b.Status.OverlayCIDR, "each network gets a distinct /72")
}
