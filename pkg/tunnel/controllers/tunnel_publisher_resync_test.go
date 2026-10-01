package controllers

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// tunnelOf returns a Tunnel of relay with no connection behind it.
func tunnelOf(name, relay string) *vpcv1alpha1.Tunnel {
	return &vpcv1alpha1.Tunnel{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{LabelRelay: relay}}}
}

// tunnelNames returns the names of the Tunnels in the apiserver.
func tunnelNames(t *testing.T, c client.Client) []string {
	t.Helper()
	var list vpcv1alpha1.TunnelList
	require.NoError(t, c.List(context.Background(), &list))
	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		names = append(names, item.Name)
	}
	slices.Sort(names)
	return names
}

// TestTunnelPublisherResync covers the sync at boot and after an outage.
func TestTunnelPublisherResync(t *testing.T) {
	notAllowed := apierrors.NewMethodNotSupported(vpcv1alpha1.Resource("tunnels"), "deletecollection")
	cases := []struct {
		name string
		// existing are the Tunnels before the connects.
		existing []client.Object
		// connect are the live connections.
		connect []string
		// lost are the Tunnels of live connections that the apiserver loses.
		lost         []string
		bulkFails    bool
		want         []string
		wantBulk     int32
		wantSingle   bool
		wantNoSingle bool
	}{
		{
			name:         "boot deletes the Tunnels of the earlier process in one request",
			existing:     []client.Object{tunnelOf("old-1", "relay-0"), tunnelOf("old-2", "relay-0"), tunnelOf("other", "relay-1")},
			want:         []string{"other"},
			wantBulk:     1,
			wantNoSingle: true,
		},
		{
			name:       "boot deletes one at a time when the bulk delete is refused",
			existing:   []client.Object{tunnelOf("old-1", "relay-0"), tunnelOf("other", "relay-1")},
			bulkFails:  true,
			want:       []string{"other"},
			wantBulk:   1,
			wantSingle: true,
		},
		{
			name:       "stale Tunnels go and live ones stay",
			existing:   []client.Object{tunnelOf("old-1", "relay-0"), tunnelOf("other", "relay-1")},
			connect:    []string{"conn-a", "conn-b"},
			want:       []string{"conn-a", "conn-b", "other"},
			wantSingle: true,
		},
		{
			name:    "lost Tunnels of live connections are created again",
			connect: []string{"conn-a", "conn-b"},
			lost:    []string{"conn-b"},
			want:    []string{"conn-a", "conn-b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var bulk, single atomic.Int32
			c := fake.NewClientBuilder().
				WithScheme(publisherScheme(t)).
				WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
				WithObjects(tc.existing...).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						single.Add(1)
						return c.Delete(ctx, obj, opts...)
					},
					DeleteAllOf: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error {
						bulk.Add(1)
						if tc.bulkFails {
							return notAllowed
						}
						return c.DeleteAllOf(ctx, obj, opts...)
					},
				}).
				Build()
			p, _ := newPublisherWithClient(t, c)
			for _, id := range tc.connect {
				require.NoError(t, p.OnConnect(ctx, "agent-"+id, "agent-"+id, &fakeConn{id: id, network: "corp"}))
			}
			settle(t, p)
			for _, id := range tc.lost {
				require.NoError(t, c.Delete(ctx, &vpcv1alpha1.Tunnel{ObjectMeta: metav1.ObjectMeta{Name: id}}))
			}
			single.Store(0)

			require.NoError(t, p.Resync(ctx))
			require.Eventually(t, func() bool { return slices.Equal(tunnelNames(t, c), tc.want) },
				2*time.Second, 5*time.Millisecond, "Tunnels = %v, want %v", tunnelNames(t, c), tc.want)
			settle(t, p)
			require.Equal(t, tc.wantBulk, bulk.Load(), "bulk deletes")
			if tc.wantSingle {
				require.NotZero(t, single.Load(), "no Tunnel was deleted one at a time")
			}
			if tc.wantNoSingle {
				require.Zero(t, single.Load(), "a Tunnel was deleted one at a time")
			}
		})
	}
}

// TestTunnelPublisherResyncRetriesNow: on a sync, the creates that wait for a
// retry go at once.
func TestTunnelPublisherResyncRetriesNow(t *testing.T) {
	ctx := context.Background()
	var down atomic.Bool
	var failed atomic.Int32
	down.Store(true)
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if down.Load() {
					failed.Add(1)
					return apierrors.NewServiceUnavailable("apiserver is down")
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		Build()
	p, _ := newPublisherWithClient(t, c)
	require.NoError(t, p.OnConnect(ctx, "agent-a", "agent-a", &fakeConn{id: "conn-a", network: "corp"}))
	// After two failures, the next retry is 2 s later.
	require.Eventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		st := p.tunnels["conn-a"]
		return failed.Load() >= 2 && st != nil && !st.busy && !st.retryAt.IsZero()
	}, 3*time.Second, 5*time.Millisecond)

	down.Store(false)
	require.NoError(t, p.Resync(ctx))
	require.Eventually(t, func() bool { return tunnelExists(t, c, "conn-a") }, time.Second, 5*time.Millisecond,
		"the Tunnel waited for its retry delay after the sync")
}

// TestTunnelPublisherResyncHoldsCreates: a Tunnel of a connect during the bulk
// delete is created only after the delete.
func TestTunnelPublisherResyncHoldsCreates(t *testing.T) {
	ctx := context.Background()
	bulkStarted := make(chan struct{})
	release := make(chan struct{})
	var created atomic.Bool
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithObjects(tunnelOf("old-1", "relay-0")).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				created.Store(true)
				return c.Create(ctx, obj, opts...)
			},
			DeleteAllOf: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error {
				close(bulkStarted)
				<-release
				return c.DeleteAllOf(ctx, obj, opts...)
			},
		}).
		Build()
	p, _ := newPublisherWithClient(t, c)

	done := make(chan error, 1)
	go func() { done <- p.Resync(ctx) }()
	<-bulkStarted
	require.NoError(t, p.OnConnect(ctx, "agent-a", "agent-a", &fakeConn{id: "conn-a", network: "corp"}))
	retryNow(p)
	require.Never(t, created.Load, 200*time.Millisecond, 10*time.Millisecond, "a Tunnel was created during the bulk delete")

	close(release)
	require.NoError(t, <-done)
	settle(t, p)
	require.Equal(t, []string{"conn-a"}, tunnelNames(t, c))
}

// TestTunnelPublisherReleaseAllBulkDelete: one request for all Tunnels at
// shutdown, or one per Tunnel when that fails.
func TestTunnelPublisherReleaseAllBulkDelete(t *testing.T) {
	cases := []struct {
		name       string
		bulkFails  bool
		wantSingle int32
	}{
		{name: "one request"},
		{name: "one request per Tunnel when the bulk delete fails", bulkFails: true, wantSingle: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var single atomic.Int32
			c := fake.NewClientBuilder().
				WithScheme(publisherScheme(t)).
				WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
				WithObjects(tunnelOf("other", "relay-1")).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						single.Add(1)
						return c.Delete(ctx, obj, opts...)
					},
					DeleteAllOf: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error {
						if tc.bulkFails {
							return apierrors.NewServiceUnavailable("no bulk delete")
						}
						return c.DeleteAllOf(ctx, obj, opts...)
					},
				}).
				Build()
			p, _ := newPublisherWithClient(t, c)
			for _, id := range []string{"conn-a", "conn-b"} {
				require.NoError(t, p.OnConnect(ctx, "agent", "agent", &fakeConn{id: id, network: "corp"}))
			}
			settle(t, p)
			p.stopWorker()
			<-p.workerDone
			for _, id := range []string{"conn-a", "conn-b"} {
				require.NoError(t, p.OnDisconnect(ctx, "agent", id))
			}

			releaseCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			require.NoError(t, p.ReleaseAll(releaseCtx))
			require.Equal(t, []string{"other"}, tunnelNames(t, c))
			require.Equal(t, tc.wantSingle, single.Load())
			p.mu.Lock()
			require.Empty(t, p.tunnels, "a Tunnel state was left after the delete")
			p.mu.Unlock()
		})
	}
}

// TestTunnelPublisherReportsWriteBacklog covers the backlog metrics during and
// after an outage.
func TestTunnelPublisherReportsWriteBacklog(t *testing.T) {
	ctx := context.Background()
	var down atomic.Bool
	down.Store(true)
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if down.Load() {
					return apierrors.NewServiceUnavailable("project apiserver is down")
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		Build()
	baseline := testutil.ToFloat64(metrics.TunnelCreatesPending)
	p, _ := newPublisherWithClient(t, c)
	for _, id := range []string{"conn-a", "conn-b"} {
		require.NoError(t, p.OnConnect(ctx, "agent", "agent", &fakeConn{id: id, network: "corp"}))
	}
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.TunnelCreatesPending) == baseline+2 &&
			testutil.ToFloat64(metrics.TunnelOldestPendingWrite) >= 0.2
	}, 3*time.Second, 10*time.Millisecond, "the backlog of two waiting creates was not reported")

	down.Store(false)
	retryNow(p)
	settle(t, p)
	require.Eventually(t, func() bool { return testutil.ToFloat64(metrics.TunnelCreatesPending) == baseline },
		3*time.Second, 10*time.Millisecond, "the backlog was not cleared")
	p.mu.Lock()
	for id, st := range p.tunnels {
		require.True(t, st.pendingSince.IsZero(), "Tunnel %s still has a pending write time", id)
	}
	p.mu.Unlock()
}
