package controllers

import (
	"context"
	"errors"
	"fmt"
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

// testExitAt is the time of the Envoy exit in the tests.
var testExitAt = metav1.NewTime(time.Unix(1_700_000_100, 0))

// testNode builds the metadata of a node whose Envoy has not exited.
func testNode(name string) *xdstypes.NodeMetadata {
	return &xdstypes.NodeMetadata{Name: name}
}

// testExitedNode builds the metadata of a node whose Envoy exited and started
// again, with the stream connected at the given time.
func testExitedNode(name string, restarts int32, connectedAt time.Time) *xdstypes.NodeMetadata {
	return &xdstypes.NodeMetadata{
		Name:          name,
		ConnectedAt:   metav1.NewTime(connectedAt),
		EnvoyRestarts: restarts,
		LastEnvoyExit: &xdstypes.NodeEnvoyExit{
			At:     testExitAt,
			Reason: "signal",
			Code:   "SIGKILL",
		},
	}
}

// testReplicaExit is the exit that testExitedNode reports, as the API type.
func testReplicaExit() *corev1alpha2.EnvoyExit {
	return &corev1alpha2.EnvoyExit{Time: testExitAt, Reason: "signal", Code: "SIGKILL"}
}

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

// TestApplyNodeMetadata covers the copy of the Envoy restart count and the last
// exit of a node into the status of a replica that the API server holds.
func TestApplyNodeMetadata(t *testing.T) {
	nodeExit := &xdstypes.NodeEnvoyExit{At: testExitAt, Reason: "exit", Code: "7"}
	replicaExit := &corev1alpha2.EnvoyExit{Time: testExitAt, Reason: "exit", Code: "7"}

	cases := []struct {
		name string
		// replica is the status the API server holds now.
		replica *corev1alpha2.ProxyReplicaStatus
		// meta is the metadata of the connected node.
		meta *xdstypes.NodeMetadata
		// want is the status the replica must end up with.
		want *corev1alpha2.ProxyReplicaStatus
		// wantChanged is true when the status must be written.
		wantChanged bool
	}{
		{
			name:    "node without exit info",
			replica: &corev1alpha2.ProxyReplicaStatus{Name: "ssr-0"},
			meta:    &xdstypes.NodeMetadata{Name: "ssr-0"},
			want:    &corev1alpha2.ProxyReplicaStatus{Name: "ssr-0"},
		},
		{
			name:    "first exit of the node",
			replica: &corev1alpha2.ProxyReplicaStatus{Name: "ssr-0"},
			meta: &xdstypes.NodeMetadata{
				Name:          "ssr-0",
				EnvoyRestarts: 1,
				LastEnvoyExit: nodeExit,
			},
			want: &corev1alpha2.ProxyReplicaStatus{
				Name:          "ssr-0",
				EnvoyRestarts: 1,
				LastEnvoyExit: replicaExit,
			},
			wantChanged: true,
		},
		{
			name: "another exit of the node",
			replica: &corev1alpha2.ProxyReplicaStatus{
				Name:          "ssr-0",
				EnvoyRestarts: 1,
				LastEnvoyExit: replicaExit.DeepCopy(),
			},
			meta: &xdstypes.NodeMetadata{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: &xdstypes.NodeEnvoyExit{At: testExitAt, Reason: "signal", Code: "SIGKILL"},
			},
			want: &corev1alpha2.ProxyReplicaStatus{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: &corev1alpha2.EnvoyExit{Time: testExitAt, Reason: "signal", Code: "SIGKILL"},
			},
			wantChanged: true,
		},
		{
			name: "same exit info",
			replica: &corev1alpha2.ProxyReplicaStatus{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: replicaExit.DeepCopy(),
			},
			meta: &xdstypes.NodeMetadata{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: nodeExit,
			},
			want: &corev1alpha2.ProxyReplicaStatus{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: replicaExit,
			},
		},
		{
			name: "backplane restarted and reports no exit",
			replica: &corev1alpha2.ProxyReplicaStatus{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: replicaExit.DeepCopy(),
			},
			meta:        &xdstypes.NodeMetadata{Name: "ssr-0"},
			want:        &corev1alpha2.ProxyReplicaStatus{Name: "ssr-0"},
			wantChanged: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := applyNodeMetadata(tc.replica, tc.meta)

			require.Equal(t, tc.wantChanged, changed)
			require.Equal(t, tc.want, tc.replica)
		})
	}
}

// TestProxyReconcilerApplyNodeUpdate covers one xDS node update against the
// status of a Proxy. Envoy gets a new node ID on every start, so the stream of
// the previous run closes after the new run connects.
func TestProxyReconcilerApplyNodeUpdate(t *testing.T) {
	ctx := context.Background()
	newRun := testExitedNode("ssr-0", 2, time.Unix(1_700_000_300, 0))

	cases := []struct {
		name string
		// replicas is the status the Proxy holds now.
		replicas []*corev1alpha2.ProxyReplicaStatus
		// nodes are the nodes of the Proxy in the xDS cache, by node ID.
		nodes map[string]*xdstypes.NodeMetadata
		// nodeID and meta describe the node of the update.
		nodeID string
		meta   *xdstypes.NodeMetadata
		// deleted is true when the stream of the node closed.
		deleted bool
		// want is the status the Proxy must end up with.
		want []*corev1alpha2.ProxyReplicaStatus
		// wantChanged is true when the status must be written.
		wantChanged bool
	}{
		{
			name:        "node of a new replica",
			nodeID:      "node-a",
			meta:        testNode("ssr-0"),
			want:        []*corev1alpha2.ProxyReplicaStatus{{Name: "ssr-0"}},
			wantChanged: true,
		},
		{
			name:     "node of a known replica after a restart",
			replicas: []*corev1alpha2.ProxyReplicaStatus{{Name: "ssr-0", EnvoyRestarts: 1}},
			nodeID:   "node-b",
			meta:     newRun,
			want: []*corev1alpha2.ProxyReplicaStatus{{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: testReplicaExit(),
			}},
			wantChanged: true,
		},
		{
			name: "last node of the replica goes",
			replicas: []*corev1alpha2.ProxyReplicaStatus{{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: testReplicaExit(),
			}},
			nodeID:  "node-a",
			meta:    testNode("ssr-0"),
			deleted: true,
			// The removal leaves an empty list, not a nil one.
			want:        []*corev1alpha2.ProxyReplicaStatus{},
			wantChanged: true,
		},
		{
			name: "late delete of the old node keeps the replica",
			replicas: []*corev1alpha2.ProxyReplicaStatus{{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: testReplicaExit(),
			}},
			nodes:   map[string]*xdstypes.NodeMetadata{"node-b": newRun},
			nodeID:  "node-a",
			meta:    testNode("ssr-0"),
			deleted: true,
			want: []*corev1alpha2.ProxyReplicaStatus{{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: testReplicaExit(),
			}},
		},
		{
			name:     "late delete of the old node takes the status of the new node",
			replicas: []*corev1alpha2.ProxyReplicaStatus{{Name: "ssr-0", EnvoyRestarts: 1}},
			nodes:    map[string]*xdstypes.NodeMetadata{"node-b": newRun},
			nodeID:   "node-a",
			meta:     testNode("ssr-0"),
			deleted:  true,
			want: []*corev1alpha2.ProxyReplicaStatus{{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: testReplicaExit(),
			}},
			wantChanged: true,
		},
		{
			name:    "node of an unknown replica goes",
			nodeID:  "node-a",
			meta:    testNode("ssr-0"),
			deleted: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &message.ProviderResources{}
			for nodeID, meta := range tc.nodes {
				res.EnvoyResources.Nodes.Store(
					message.NodeKey{ClusterName: "ssr", NodeID: nodeID},
					meta,
				)
			}
			r := NewProxyReconciler(ctx, newProxyClient(t), res,
				&errIPAM{err: errors.New("ipam is not reachable")}, func() {})

			p := &corev1alpha2.Proxy{ObjectMeta: metav1.ObjectMeta{Name: "ssr"}}
			p.Status.Replicas = tc.replicas

			changed := r.applyNodeUpdate(p, tc.nodeID, tc.meta, tc.deleted)

			require.Equal(t, tc.wantChanged, changed)
			require.Equal(t, tc.want, p.Status.Replicas)
		})
	}
}

// TestProxyReconcilerResyncReplicas covers the resync of replicas against the
// nodes that are connected now, including Proxies without connected nodes.
func TestProxyReconcilerResyncReplicas(t *testing.T) {
	ctx := context.Background()

	proxyWithReplicas := func(name string, replicas ...*corev1alpha2.ProxyReplicaStatus) *corev1alpha2.Proxy {
		p := &corev1alpha2.Proxy{ObjectMeta: metav1.ObjectMeta{Name: name}}
		p.Status.Replicas = append(p.Status.Replicas, replicas...)
		return p
	}

	proxyWith := func(name string, replicas ...string) *corev1alpha2.Proxy {
		p := &corev1alpha2.Proxy{ObjectMeta: metav1.ObjectMeta{Name: name}}
		for _, replica := range replicas {
			p.Status.Replicas = append(p.Status.Replicas, &corev1alpha2.ProxyReplicaStatus{Name: replica})
		}
		return p
	}

	node := testNode

	exitedNode := func(name string, restarts int32) *xdstypes.NodeMetadata {
		return testExitedNode(name, restarts, time.Unix(1_700_000_200, 0))
	}

	wantExit := testReplicaExit()

	cases := []struct {
		name string
		// proxies are the Proxy objects the API server holds.
		proxies []client.Object
		// nodes maps a proxy name to the metadata of its connected nodes.
		nodes map[string][]*xdstypes.NodeMetadata
		// want maps a proxy name to the replica names it must end up with.
		want map[string][]string
		// wantRestarts maps a replica name to the restart count it must hold.
		wantRestarts map[string]int32
		// wantLastExit maps a replica name to the last Envoy exit it must hold.
		wantLastExit map[string]*corev1alpha2.EnvoyExit
		// wantNoWrite is true when no Proxy status may be written.
		wantNoWrite bool
	}{
		{
			name:    "proxy without connected nodes loses every replica",
			proxies: []client.Object{proxyWith("ssr", "ssr-0", "ssr-1")},
			want:    map[string][]string{"ssr": nil},
		},
		{
			name:    "stale replica goes and connected replica stays",
			proxies: []client.Object{proxyWith("ssr", "ssr-0", "ssr-1")},
			nodes:   map[string][]*xdstypes.NodeMetadata{"ssr": {node("ssr-1")}},
			want:    map[string][]string{"ssr": {"ssr-1"}},
		},
		{
			name:    "connected node without a replica is added",
			proxies: []client.Object{proxyWith("ssr")},
			nodes:   map[string][]*xdstypes.NodeMetadata{"ssr": {node("ssr-0")}},
			want:    map[string][]string{"ssr": {"ssr-0"}},
		},
		{
			name: "proxy without nodes is pruned next to a live proxy",
			proxies: []client.Object{
				proxyWith("ssr", "ssr-0"),
				proxyWith("live", "live-0"),
			},
			nodes: map[string][]*xdstypes.NodeMetadata{"live": {node("live-0")}},
			want: map[string][]string{
				"ssr":  nil,
				"live": {"live-0"},
			},
		},
		{
			name:         "new replica with exit info",
			proxies:      []client.Object{proxyWith("ssr")},
			nodes:        map[string][]*xdstypes.NodeMetadata{"ssr": {exitedNode("ssr-0", 2)}},
			want:         map[string][]string{"ssr": {"ssr-0"}},
			wantRestarts: map[string]int32{"ssr-0": 2},
			wantLastExit: map[string]*corev1alpha2.EnvoyExit{"ssr-0": wantExit},
		},
		{
			name:    "two nodes of one replica, the newest wins",
			proxies: []client.Object{proxyWith("ssr")},
			nodes: map[string][]*xdstypes.NodeMetadata{"ssr": {
				testExitedNode("ssr-0", 1, time.Unix(1_700_000_300, 0)),
				testExitedNode("ssr-0", 0, time.Unix(1_700_000_100, 0)),
			}},
			want:         map[string][]string{"ssr": {"ssr-0"}},
			wantRestarts: map[string]int32{"ssr-0": 1},
			wantLastExit: map[string]*corev1alpha2.EnvoyExit{"ssr-0": wantExit},
		},
		{
			name:         "existing replica, restarts changed, status updated",
			proxies:      []client.Object{proxyWithReplicas("ssr", &corev1alpha2.ProxyReplicaStatus{Name: "ssr-0", EnvoyRestarts: 1})},
			nodes:        map[string][]*xdstypes.NodeMetadata{"ssr": {exitedNode("ssr-0", 2)}},
			want:         map[string][]string{"ssr": {"ssr-0"}},
			wantRestarts: map[string]int32{"ssr-0": 2},
			wantLastExit: map[string]*corev1alpha2.EnvoyExit{"ssr-0": wantExit},
		},
		{
			name: "unchanged, no write",
			proxies: []client.Object{proxyWithReplicas("ssr", &corev1alpha2.ProxyReplicaStatus{
				Name:          "ssr-0",
				EnvoyRestarts: 2,
				LastEnvoyExit: wantExit.DeepCopy(),
			})},
			nodes:        map[string][]*xdstypes.NodeMetadata{"ssr": {exitedNode("ssr-0", 2)}},
			want:         map[string][]string{"ssr": {"ssr-0"}},
			wantRestarts: map[string]int32{"ssr-0": 2},
			wantLastExit: map[string]*corev1alpha2.EnvoyExit{"ssr-0": wantExit},
			wantNoWrite:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newProxyClient(t, tc.proxies...)
			res := &message.ProviderResources{}
			for proxyName, nodes := range tc.nodes {
				for i, meta := range nodes {
					res.EnvoyResources.Nodes.Store(
						message.NodeKey{ClusterName: proxyName, NodeID: fmt.Sprintf("%s-%d", meta.Name, i)},
						meta,
					)
				}
			}
			r := NewProxyReconciler(ctx, c, res, &errIPAM{err: errors.New("ipam is not reachable")}, func() {})

			versions := make(map[string]string)
			for proxyName := range tc.want {
				before := &corev1alpha2.Proxy{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{Name: proxyName}, before))
				versions[proxyName] = before.ResourceVersion
			}

			r.resyncReplicas(ctx)

			for proxyName, wantReplicas := range tc.want {
				got := &corev1alpha2.Proxy{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{Name: proxyName}, got))

				var names []string
				for _, replica := range got.Status.Replicas {
					names = append(names, replica.Name)

					if want, ok := tc.wantRestarts[replica.Name]; ok {
						require.Equal(t, want, replica.EnvoyRestarts, "restarts of replica %q", replica.Name)
					}
					if want, ok := tc.wantLastExit[replica.Name]; ok {
						require.Equal(t, want, replica.LastEnvoyExit, "last exit of replica %q", replica.Name)
					}
				}
				require.ElementsMatch(t, wantReplicas, names, "replicas of Proxy %q", proxyName)

				if tc.wantNoWrite {
					require.Equal(t, versions[proxyName], got.ResourceVersion,
						"status of Proxy %q was written", proxyName)
				}
				versions[proxyName] = got.ResourceVersion
			}

			// The status matches the connected nodes now, so a second resync
			// must leave every Proxy as it is.
			r.resyncReplicas(ctx)

			for proxyName := range tc.want {
				got := &corev1alpha2.Proxy{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{Name: proxyName}, got))
				require.Equal(t, versions[proxyName], got.ResourceVersion,
					"second resync wrote the status of Proxy %q", proxyName)
			}
		})
	}
}
