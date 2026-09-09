package controllers

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	xdstypes "github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	tunnelnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// errIPAM is an IPAM that always fails, to check that a release error stops the
// removal of the finalizer.
type errIPAM struct {
	err error
}

func (e *errIPAM) Allocate() (netip.Prefix, error) { return netip.Prefix{}, e.err }

func (e *errIPAM) Release(netip.Prefix) error { return e.err }

func proxyScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1alpha2.Install(s))
	return s
}

// deletingProxy builds a Proxy that carries the finalizer and is being deleted,
// with one replica holding the given overlay address.
func deletingProxy(name, replica, ulaAddr string) *corev1alpha2.Proxy {
	deleted := metav1.NewTime(time.Unix(1_700_000_000, 0))
	p := &corev1alpha2.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Finalizers:        []string{corev1alpha2.ProxyFinalizer},
			DeletionTimestamp: &deleted,
		},
		Status: corev1alpha2.ProxyStatus{
			Replicas: []*corev1alpha2.ProxyReplicaStatus{{Name: replica}},
		},
	}
	if ulaAddr != "" {
		p.Status.Replicas[0].Addresses = []corev1alpha2.ReplicaAddress{{
			Type:    corev1alpha2.ReplicaInternalULA,
			Address: ulaAddr,
		}}
	}
	return p
}

func newProxyClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(proxyScheme(t)).
		WithStatusSubresource(&corev1alpha2.Proxy{}).
		WithObjects(objs...).
		Build()
}

// TestProxyReconcilerDelete covers the release of replica addresses when a
// Proxy is deleted. The IPAM holds its allocations in memory only, so after a
// restart it knows none of the addresses in the status of the Proxy.
func TestProxyReconcilerDelete(t *testing.T) {
	ctx := context.Background()

	// restartedIPAM is an empty IPAM, as it is after a process restart.
	restartedIPAM := func(t *testing.T) tunnelnet.IPAM {
		t.Helper()
		ipam, err := tunnelnet.NewULA(ctx, tunnelnet.SystemNetworkID).IPAM(ctx, 128)
		require.NoError(t, err)
		return ipam
	}

	cases := []struct {
		name string
		// ipam builds the IPAM and returns the address held by the replica.
		ipam func(t *testing.T) (tunnelnet.IPAM, string)
		// wantErr is true when the reconcile must fail.
		wantErr bool
		// wantFinalizer is true when the Proxy must keep its finalizer.
		wantFinalizer bool
	}{
		{
			name: "address is unknown to the ipam",
			ipam: func(t *testing.T) (tunnelnet.IPAM, string) {
				return restartedIPAM(t), "fd61:706f:7879::e1d"
			},
		},
		{
			name: "address is unknown but the ipam holds others",
			ipam: func(t *testing.T) (tunnelnet.IPAM, string) {
				ipam := restartedIPAM(t)
				_, err := ipam.Allocate()
				require.NoError(t, err)
				return ipam, "fd61:706f:7879::e1d"
			},
		},
		{
			name: "address is held by the ipam",
			ipam: func(t *testing.T) (tunnelnet.IPAM, string) {
				ipam := restartedIPAM(t)
				addr, err := ipam.Allocate()
				require.NoError(t, err)
				return ipam, addr.Addr().String()
			},
		},
		{
			name: "replica has no overlay address",
			ipam: func(t *testing.T) (tunnelnet.IPAM, string) {
				return &errIPAM{err: errors.New("ipam is not reachable")}, ""
			},
		},
		{
			name: "release fails",
			ipam: func(t *testing.T) (tunnelnet.IPAM, string) {
				return &errIPAM{err: errors.New("ipam is not reachable")}, "fd61:706f:7879::e1d"
			},
			wantErr:       true,
			wantFinalizer: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ipam, ulaAddr := tc.ipam(t)
			p := deletingProxy("ssr", "ssr-0", ulaAddr)
			c := newProxyClient(t, p)
			r := NewProxyReconciler(ctx, c, &message.ProviderResources{}, ipam, func() {})

			_, err := r.reconcileRequest(ctx, reconcile.Request{
				NamespacedName: client.ObjectKey{Name: "ssr"},
			})
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			got := &corev1alpha2.Proxy{}
			err = c.Get(ctx, client.ObjectKey{Name: "ssr"}, got)
			if !tc.wantFinalizer {
				// The fake client drops the object once the last finalizer goes.
				require.True(t, apierrors.IsNotFound(err), "Proxy still has the finalizer")
				return
			}
			require.NoError(t, err)
			require.True(t, controllerutil.ContainsFinalizer(got, corev1alpha2.ProxyFinalizer))
		})
	}
}

// TestProxyReconcilerResyncReplicas covers the resync of replicas against the
// nodes that are connected now, including Proxies without connected nodes.
func TestProxyReconcilerResyncReplicas(t *testing.T) {
	ctx := context.Background()

	proxyWith := func(name string, replicas ...string) *corev1alpha2.Proxy {
		p := &corev1alpha2.Proxy{ObjectMeta: metav1.ObjectMeta{Name: name}}
		for _, replica := range replicas {
			p.Status.Replicas = append(p.Status.Replicas, &corev1alpha2.ProxyReplicaStatus{Name: replica})
		}
		return p
	}

	cases := []struct {
		name string
		// proxies are the Proxy objects the API server holds.
		proxies []client.Object
		// nodes maps a proxy name to the names of its connected nodes.
		nodes map[string][]string
		// want maps a proxy name to the replica names it must end up with.
		want map[string][]string
	}{
		{
			name:    "proxy without connected nodes loses every replica",
			proxies: []client.Object{proxyWith("ssr", "ssr-0", "ssr-1")},
			want:    map[string][]string{"ssr": nil},
		},
		{
			name:    "stale replica goes and connected replica stays",
			proxies: []client.Object{proxyWith("ssr", "ssr-0", "ssr-1")},
			nodes:   map[string][]string{"ssr": {"ssr-1"}},
			want:    map[string][]string{"ssr": {"ssr-1"}},
		},
		{
			name:    "connected node without a replica is added",
			proxies: []client.Object{proxyWith("ssr")},
			nodes:   map[string][]string{"ssr": {"ssr-0"}},
			want:    map[string][]string{"ssr": {"ssr-0"}},
		},
		{
			name: "proxy without nodes is pruned next to a live proxy",
			proxies: []client.Object{
				proxyWith("ssr", "ssr-0"),
				proxyWith("live", "live-0"),
			},
			nodes: map[string][]string{"live": {"live-0"}},
			want: map[string][]string{
				"ssr":  nil,
				"live": {"live-0"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newProxyClient(t, tc.proxies...)
			res := &message.ProviderResources{}
			for proxyName, nodes := range tc.nodes {
				for _, node := range nodes {
					res.EnvoyResources.Nodes.Store(
						message.NodeKey{ClusterName: proxyName, NodeID: node},
						&xdstypes.NodeMetadata{Name: node},
					)
				}
			}
			r := NewProxyReconciler(ctx, c, res, &errIPAM{err: errors.New("ipam is not reachable")}, func() {})

			r.resyncReplicas(ctx)

			for proxyName, wantReplicas := range tc.want {
				got := &corev1alpha2.Proxy{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{Name: proxyName}, got))

				var names []string
				for _, replica := range got.Status.Replicas {
					names = append(names, replica.Name)
				}
				require.ElementsMatch(t, wantReplicas, names, "replicas of Proxy %q", proxyName)
			}
		})
	}
}
