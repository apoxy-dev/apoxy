package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

// fakeConn is a controllers.Connection stub that records what the publisher
// assigns without touching a real router or icx handler.
type fakeConn struct {
	id            string
	network       string
	labels        map[string]string
	routes        []netip.Prefix
	agentInstance string

	// setAddrsErr, when set, decides each SetAddresses call, so a test can
	// reject one address family the way a failed route add does.
	setAddrsErr func([]string) error
	// onSetOverlay, when set, runs inside SetOverlayAddress.
	onSetOverlay func()

	overlay   string
	vniID     *uint
	addresses []string
	setAddrs  [][]string
	closed    bool
}

func (c *fakeConn) ID() string   { return c.id }
func (c *fakeConn) Close() error { c.closed = true; return nil }
func (c *fakeConn) SetOverlayAddress(a string) error {
	if c.onSetOverlay != nil {
		c.onSetOverlay()
	}
	c.overlay = a
	return nil
}
func (c *fakeConn) SetVNI(_ context.Context, v uint) error { c.vniID = &v; return nil }
func (c *fakeConn) Stats() (ConnectionStats, bool)         { return ConnectionStats{}, false }
func (c *fakeConn) Network() string                        { return c.network }
func (c *fakeConn) Scope() string                          { return "" }
func (c *fakeConn) Labels() map[string]string              { return c.labels }
func (c *fakeConn) AdvertisedRoutes() []netip.Prefix       { return c.routes }
func (c *fakeConn) AgentInstance() string                  { return c.agentInstance }
func (c *fakeConn) Addresses() []string                    { return c.addresses }

func (c *fakeConn) SetAddresses(a []string) error {
	c.setAddrs = append(c.setAddrs, a)
	if c.setAddrsErr != nil {
		if err := c.setAddrsErr(a); err != nil {
			return err
		}
	}
	c.addresses = a
	return nil
}

func publisherScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, vpcv1alpha1.Install(s))
	return s
}

// newPublisher builds a TunnelPublisher over a fake client + local leaser and
// resolves one network ("corp").
func newPublisher(t *testing.T) (*TunnelPublisher, client.Client, tunnet.NetworkID) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		Build()
	p, netID := newPublisherWithClient(t, c)
	return p, c, netID
}

// newPublisherWithClient builds a TunnelPublisher over c + a local leaser and
// resolves one network ("corp").
func newPublisherWithClient(t *testing.T, c client.Client) (*TunnelPublisher, tunnet.NetworkID) {
	t.Helper()
	p := NewTunnelPublisher(c, stubRelay{name: "relay-0"}, ipalloc.NewLocalSlotLeaser(), vni.NewVNIAllocator())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		p.ReleaseAll(ctx)
	})
	netID := tunnet.NetworkID{0x00, 0x00, 0x01}
	p.SetNetworkID("corp", netID)
	return p, netID
}

// settle waits until the publisher has no Tunnel work left.
func settle(t *testing.T, p *TunnelPublisher) {
	t.Helper()
	require.Eventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, st := range p.tunnels {
			if st.busy || st.needsDelete() || st.needsCreate() {
				return false
			}
		}
		return true
	}, 5*time.Second, 5*time.Millisecond, "Tunnel writes did not settle")
}

// retryNow makes every pending Tunnel write due and wakes the worker.
func retryNow(p *TunnelPublisher) {
	p.mu.Lock()
	for _, st := range p.tunnels {
		st.retryAt = time.Time{}
	}
	p.mu.Unlock()
	p.wakeWorker()
}

// tunnelExists reports whether the Tunnel named name is in the apiserver.
func tunnelExists(t *testing.T, c client.Client, name string) bool {
	t.Helper()
	err := c.Get(context.Background(), client.ObjectKey{Name: name}, &vpcv1alpha1.Tunnel{})
	if apierrors.IsNotFound(err) {
		return false
	}
	require.NoError(t, err)
	return true
}

func TestTunnelPublisherOnConnectCreatesTunnel(t *testing.T) {
	ctx := context.Background()
	p, c, _ := newPublisher(t)

	conn := &fakeConn{
		id:      "conn-a",
		network: "corp",
		labels: map[string]string{
			"app":                       "payments",
			LabelRelay:                  "forged-relay",
			ipalloc.LabelSlot:           "ffffff-ffff",
			ipalloc.LabelSlotGeneration: "999",
		},
		routes:        []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		agentInstance: "uuid-1",
	}
	require.NoError(t, p.OnConnect(ctx, "agent-a", "agent-a", conn))

	// The connection was assigned a VNI + primary overlay + dual-stack set.
	require.NotNil(t, conn.vniID)
	require.NotEmpty(t, conn.overlay)
	require.NotEmpty(t, conn.addresses)
	require.Equal(t, conn.overlay, conn.addresses[0], "primary address is the programmed overlay")

	settle(t, p)
	var got vpcv1alpha1.Tunnel
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "conn-a"}, &got))
	require.Equal(t, "corp", got.Spec.NetworkRef.Name)
	require.Equal(t, "relay-0", got.Spec.RelayRef.Name)
	require.Equal(t, conn.addresses, got.Status.Addresses)
	require.Equal(t, []string{"10.20.0.0/16"}, got.Status.AdvertisedRoutes)

	// The relay adds identity labels next to the agent label.
	require.Equal(t, "payments", got.Labels["app"])
	require.Equal(t, "corp", got.Labels[vpcv1alpha1.LabelNetwork])
	require.Equal(t, "agent-a", got.Labels[vpcv1alpha1.LabelTunnelName])
	require.Equal(t, "relay-0", got.Labels[LabelRelay])
	require.Equal(t, "000001-0100", got.Labels[ipalloc.LabelSlot])
	require.Equal(t, "1", got.Labels[ipalloc.LabelSlotGeneration])
	require.Equal(t, "uuid-1", got.Labels[vpcv1alpha1.LabelAgentInstance])
}

type slotLossRelay struct {
	stubRelay
	disconnected []string
}

func (r *slotLossRelay) DisconnectConnection(id string) {
	r.disconnected = append(r.disconnected, id)
}

func TestTunnelPublisherSlotLossDisconnectsExactGeneration(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		Build()
	relay := &slotLossRelay{stubRelay: stubRelay{name: "relay-0"}}
	p := NewTunnelPublisher(c, relay, ipalloc.NewLocalSlotLeaser(), vni.NewVNIAllocator())
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		p.ReleaseAll(stopCtx)
	})
	p.SetNetworkID("corp", tunnet.NetworkID{0, 0, 1})

	first := &fakeConn{id: "conn-slot-a", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-a", "agent-a", first))
	p.mu.Lock()
	lost := p.tunnels[first.ID()].live.slot
	newGeneration := lost
	newGeneration.Generation++
	p.tunnels["conn-slot-new-generation"] = &tunnelState{live: &connAlloc{slot: newGeneration}}
	p.mu.Unlock()
	p.InvalidateSlot(lost)
	require.Equal(t, []string{first.ID()}, relay.disconnected)

	second := &fakeConn{id: "conn-slot-b", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-b", "agent-b", second))
	firstSlot, _, ok := ipalloc.SlotOf(netip.MustParsePrefix(first.overlay))
	require.True(t, ok)
	secondSlot, _, ok := ipalloc.SlotOf(netip.MustParsePrefix(second.overlay))
	require.True(t, ok)
	require.NotEqual(t, firstSlot.ID, secondSlot.ID, "lost slot accepted a new allocation")
}

func TestTunnelPublisherRejectsConnectionThatLosesSlotDuringSetup(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		Build()
	relay := &slotLossRelay{stubRelay: stubRelay{name: "relay-0"}}
	p := NewTunnelPublisher(c, relay, ipalloc.NewLocalSlotLeaser(), vni.NewVNIAllocator())
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		p.ReleaseAll(stopCtx)
	})
	netID := tunnet.NetworkID{0, 0, 1}
	p.SetNetworkID("corp", netID)

	var lostSlot ipalloc.Slot
	conn := &fakeConn{id: "conn-in-flight", network: "corp"}
	conn.onSetOverlay = func() {
		// The slot is lost after allocation and before the connection is recorded.
		p.slots.mu.Lock()
		for _, a := range p.slots.nets[netID].allocs {
			if !a.Empty() {
				lostSlot = a.Slot()
			}
		}
		p.slots.mu.Unlock()
		p.InvalidateSlot(lostSlot)
	}
	err := p.OnConnect(ctx, "agent-in-flight", "agent-in-flight", conn)
	require.ErrorContains(t, err, "was lost during connection setup")
	require.Empty(t, relay.disconnected, "in-flight connection was not yet available for a direct disconnect")

	// The relay tears down a connection when OnConnect returns an error. Mirror
	// that callback: the allocation goes back and no Tunnel is ever written.
	require.NoError(t, p.OnDisconnect(ctx, "agent-in-flight", conn.ID()))
	settle(t, p)
	require.False(t, tunnelExists(t, c, conn.ID()), "Tunnel from the lost slot was written")
	p.mu.Lock()
	require.Empty(t, p.tunnels, "state of the failed connection remained")
	p.mu.Unlock()
}

// TestTunnelPublisherOnConnectV4Failure: a connection that cannot get a /32
// comes up v6-only instead of being refused.
func TestTunnelPublisherOnConnectV4Failure(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		failOn     func([]string) error
		wantErr    bool
		wantV4     bool
		wantTunnel bool
	}{
		{
			name: "v4 route rejected degrades to v6-only",
			failOn: func(a []string) error {
				if len(a) > 1 {
					return fmt.Errorf("router.AddRoute(%s) failed: file exists", a[1])
				}
				return nil
			},
			wantV4:     false,
			wantTunnel: true,
		},
		{
			name:       "a failure that outlives the /32 still refuses the connect",
			failOn:     func([]string) error { return fmt.Errorf("virtual network gone") },
			wantErr:    true,
			wantTunnel: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, c, _ := newPublisher(t)
			conn := &fakeConn{id: "conn-v4", network: "corp", setAddrsErr: tc.failOn}

			err := p.OnConnect(ctx, "agent-v4", "agent-v4", conn)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, conn.addresses)
				require.Equal(t, conn.overlay, conn.addresses[0])
				require.Len(t, conn.addresses, 1, "the connection kept only its /96")
				require.Len(t, conn.setAddrs, 2, "the /32 was attempted, then dropped")
			}

			settle(t, p)
			require.Equal(t, tc.wantTunnel, tunnelExists(t, c, "conn-v4"), "Tunnel presence")

			// Either way the /32 went back: the next connection is handed one.
			next := &fakeConn{id: "conn-next", network: "corp"}
			require.NoError(t, p.OnConnect(ctx, "agent-next", "agent-next", next))
			require.Len(t, next.addresses, 2, "the dropped /32 was returned to the slot")
		})
	}
}

func TestTunnelPublisherOnDisconnectDeletesAndReleases(t *testing.T) {
	ctx := context.Background()
	p, c, _ := newPublisher(t)

	conn := &fakeConn{id: "conn-b", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-b", "agent-b", conn))
	firstOverlay := conn.overlay
	settle(t, p)
	require.True(t, tunnelExists(t, c, "conn-b"))

	require.NoError(t, p.OnDisconnect(ctx, "agent-b", "conn-b"))
	settle(t, p)
	require.False(t, tunnelExists(t, c, "conn-b"), "Tunnel deleted on disconnect")

	// The released /96 is the lowest free slot, so the next connect reuses it.
	conn2 := &fakeConn{id: "conn-c", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-c", "agent-c", conn2))
	require.Equal(t, firstOverlay, conn2.overlay, "freed /96 is reused")
}

// TestTunnelPublisherReconnectDoesNotWaitForCleanup: a reconnect with the same
// ID gets new addresses at once; its Tunnel waits for the old delete.
func TestTunnelPublisherReconnectDoesNotWaitForCleanup(t *testing.T) {
	ctx := context.Background()
	deleteStarted := make(chan struct{})
	allowDelete := make(chan struct{})
	var blockDelete atomic.Bool
	blockDelete.Store(true)
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if blockDelete.CompareAndSwap(true, false) {
					close(deleteStarted)
					<-allowDelete
				}
				return c.Delete(ctx, obj, opts...)
			},
		}).
		Build()
	p, _ := newPublisherWithClient(t, c)

	oldConn := &fakeConn{id: "conn-reused", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-old", "agent-old", oldConn))
	settle(t, p)
	require.NoError(t, p.OnDisconnect(ctx, "agent-old", oldConn.ID()))
	<-deleteStarted

	newConn := &fakeConn{id: oldConn.ID(), network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-new", "agent-new", newConn))
	require.NotEqual(t, oldConn.overlay, newConn.overlay, "quarantined /96 was reused before the old Tunnel was deleted")

	var tunnel vpcv1alpha1.Tunnel
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: newConn.ID()}, &tunnel))
	require.Equal(t, "agent-old", tunnel.Labels[vpcv1alpha1.LabelTunnelName], "new Tunnel written before the old one was deleted")

	close(allowDelete)
	settle(t, p)
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: newConn.ID()}, &tunnel))
	require.Equal(t, "agent-new", tunnel.Labels[vpcv1alpha1.LabelTunnelName])
	require.Equal(t, []string{newConn.overlay, newConn.addresses[1]}, tunnel.Status.Addresses)

	// The old /96 went back after its Tunnel was deleted.
	next := &fakeConn{id: "conn-next", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-next", "agent-next", next))
	require.Equal(t, oldConn.overlay, next.overlay, "old /96 was not released after the delete")
}

// TestTunnelPublisherQuarantinesUntilTunnelIsGone: an allocation stays out of
// the pool until a retry confirms its Tunnel is gone.
func TestTunnelPublisherQuarantinesUntilTunnelIsGone(t *testing.T) {
	ctx := context.Background()

	setFinalizer := func(t *testing.T, c client.Client, name string, finalizers []string) {
		var tunnel vpcv1alpha1.Tunnel
		require.NoError(t, c.Get(ctx, client.ObjectKey{Name: name}, &tunnel))
		tunnel.Finalizers = finalizers
		require.NoError(t, c.Update(ctx, &tunnel))
	}
	cases := []struct {
		name string
		hold func(t *testing.T, c client.Client, failing *atomic.Bool, name string)
		free func(t *testing.T, c client.Client, failing *atomic.Bool, name string)
	}{
		{
			name: "delete fails",
			hold: func(_ *testing.T, _ client.Client, failing *atomic.Bool, _ string) { failing.Store(true) },
			free: func(_ *testing.T, _ client.Client, failing *atomic.Bool, _ string) { failing.Store(false) },
		},
		{
			name: "finalizer keeps the Tunnel",
			hold: func(t *testing.T, c client.Client, _ *atomic.Bool, name string) {
				setFinalizer(t, c, name, []string{"test.apoxy.dev/hold"})
			},
			free: func(t *testing.T, c client.Client, _ *atomic.Bool, name string) {
				setFinalizer(t, c, name, nil)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var failing atomic.Bool
			c := fake.NewClientBuilder().
				WithScheme(publisherScheme(t)).
				WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						if failing.Load() {
							return fmt.Errorf("apiserver unavailable")
						}
						return c.Delete(ctx, obj, opts...)
					},
				}).
				Build()
			p, _ := newPublisherWithClient(t, c)

			conn := &fakeConn{id: "conn-d", network: "corp"}
			require.NoError(t, p.OnConnect(ctx, "agent-d", "agent-d", conn))
			firstOverlay := conn.overlay
			settle(t, p)

			tc.hold(t, c, &failing, conn.ID())
			require.NoError(t, p.OnDisconnect(ctx, "agent-d", conn.ID()))
			require.Eventually(t, func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				st := p.tunnels[conn.ID()]
				return st != nil && st.attempts > 0
			}, 2*time.Second, 10*time.Millisecond, "failed delete was not kept for retry")

			next := &fakeConn{id: "conn-e", network: "corp"}
			require.NoError(t, p.OnConnect(ctx, "agent-e", "agent-e", next))
			require.NotEqual(t, firstOverlay, next.overlay, "address reused before the Tunnel was gone")

			tc.free(t, c, &failing, conn.ID())
			retryNow(p)
			settle(t, p)
			require.False(t, tunnelExists(t, c, conn.ID()))

			reused := &fakeConn{id: "conn-f", network: "corp"}
			require.NoError(t, p.OnConnect(ctx, "agent-f", "agent-f", reused))
			require.Equal(t, firstOverlay, reused.overlay, "address stayed quarantined after the Tunnel was gone")
		})
	}
}

func TestTunnelPublisherOnConnectUnresolvedNetwork(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPublisher(t)

	conn := &fakeConn{id: "conn-x", network: "unknown"}
	err := p.OnConnect(ctx, "agent-x", "agent-x", conn)
	require.Error(t, err, "connect to an unprovisioned network fails")
	require.Nil(t, conn.vniID, "nothing assigned when the network is unresolved")
}

func TestTunnelPublisherOnDisconnectOrphan(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPublisher(t)
	// No allocation record and no Tunnel object: disconnect is a safe no-op.
	require.NoError(t, p.OnDisconnect(ctx, "agent-z", "conn-z"))
}

// TestTunnelPublisherConnectsWhileAPIServerIsDown: connects work with every
// Tunnel call failing, and the Tunnel is written when the apiserver is back.
func TestTunnelPublisherConnectsWhileAPIServerIsDown(t *testing.T) {
	ctx := context.Background()
	var down atomic.Bool
	down.Store(true)
	unavailable := apierrors.NewServiceUnavailable("project apiserver is down")
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if down.Load() {
					return unavailable
				}
				return c.Create(ctx, obj, opts...)
			},
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if down.Load() {
					return unavailable
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	p, _ := newPublisherWithClient(t, c)

	conn := &fakeConn{id: "conn-offline", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-offline", "agent-offline", conn))
	require.NotEmpty(t, conn.overlay)
	require.Eventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.tunnels[conn.ID()].attempts > 0
	}, 2*time.Second, 10*time.Millisecond, "the Tunnel write was not tried")

	down.Store(false)
	retryNow(p)
	settle(t, p)
	var got vpcv1alpha1.Tunnel
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: conn.ID()}, &got))
	require.Equal(t, conn.addresses, got.Status.Addresses)
}

// TestTunnelPublisherDisconnectBeforeWrite: addresses of a connection closed
// before its Tunnel write go back at once with no apiserver call.
func TestTunnelPublisherDisconnectBeforeWrite(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				calls.Add(1)
				return c.Create(ctx, obj, opts...)
			},
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				calls.Add(1)
				return c.Delete(ctx, obj, opts...)
			},
		}).
		Build()
	p, _ := newPublisherWithClient(t, c)
	// Hold the worker so the disconnect comes before any write.
	p.stopWorker()
	<-p.workerDone

	conn := &fakeConn{id: "conn-brief", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-brief", "agent-brief", conn))
	require.NoError(t, p.OnDisconnect(ctx, "agent-brief", conn.ID()))

	p.mu.Lock()
	require.Empty(t, p.tunnels)
	p.mu.Unlock()
	next := &fakeConn{id: "conn-next", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-next", "agent-next", next))
	require.Equal(t, conn.overlay, next.overlay, "addresses were not released at disconnect")
	require.Zero(t, calls.Load(), "a Tunnel call was made for a connection that was never written")
}

// TestTunnelPublisherCreateFindsExistingTunnel covers a create that finds a
// Tunnel with the same name.
func TestTunnelPublisherCreateFindsExistingTunnel(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		// labels of the Tunnel present before the connect; nil means an earlier
		// create of this same connection reached the apiserver.
		labels map[string]string
	}{
		{name: "earlier attempt of the same connection"},
		{
			name: "Tunnel of an older connection",
			labels: map[string]string{
				LabelRelay:                  "relay-0",
				ipalloc.LabelSlot:           "000001-0100",
				ipalloc.LabelSlotGeneration: "7",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var lostReply atomic.Bool
			lostReply.Store(tc.labels == nil)
			c := fake.NewClientBuilder().
				WithScheme(publisherScheme(t)).
				WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
				WithInterceptorFuncs(interceptor.Funcs{
					Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						if err := c.Create(ctx, obj, opts...); err != nil {
							return err
						}
						if lostReply.CompareAndSwap(true, false) {
							return context.DeadlineExceeded
						}
						return nil
					},
				}).
				Build()
			if tc.labels != nil {
				require.NoError(t, c.Create(ctx, &vpcv1alpha1.Tunnel{
					ObjectMeta: metav1.ObjectMeta{Name: "conn-existing", Labels: tc.labels},
				}))
			}
			p, _ := newPublisherWithClient(t, c)

			conn := &fakeConn{id: "conn-existing", network: "corp"}
			require.NoError(t, p.OnConnect(ctx, "agent-new", "agent-new", conn))
			require.Eventually(t, func() bool {
				var got vpcv1alpha1.Tunnel
				if err := c.Get(ctx, client.ObjectKey{Name: conn.ID()}, &got); err != nil {
					retryNow(p)
					return false
				}
				if got.Labels[vpcv1alpha1.LabelTunnelName] != "agent-new" || len(got.Status.Addresses) == 0 {
					retryNow(p)
					return false
				}
				return true
			}, 5*time.Second, 10*time.Millisecond, "Tunnel of the new connection was not written")
		})
	}
}

// TestTunnelPublisherReleaseAll covers shutdown: slots go back, the Tunnel of
// a closed connection is deleted, and a Tunnel not yet written is not created.
func TestTunnelPublisherReleaseAll(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		Build()
	leaser := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser()}
	p := NewTunnelPublisher(c, stubRelay{name: "relay-0"}, leaser, vni.NewVNIAllocator())
	p.SetNetworkID("corp", tunnet.NetworkID{0x00, 0x00, 0x01})

	closed := &fakeConn{id: "conn-closed", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-closed", "agent-closed", closed))
	settle(t, p)
	// Hold the worker so the delete is left for ReleaseAll.
	p.stopWorker()
	<-p.workerDone
	require.NoError(t, p.OnDisconnect(ctx, "agent-closed", closed.ID()))

	unwritten := &fakeConn{id: "conn-unwritten", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent-unwritten", "agent-unwritten", unwritten))

	releaseCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	require.NoError(t, p.ReleaseAll(releaseCtx))

	require.False(t, tunnelExists(t, c, closed.ID()), "Tunnel of the closed connection was not deleted")
	require.False(t, tunnelExists(t, c, unwritten.ID()), "Tunnel was created after ReleaseAll")
	require.Equal(t, leaser.leaseCount(), leaser.releaseCount(), "a leased slot was not released")
	_, _, _, err := p.slots.Allocate(ctx, tunnet.NetworkID{0x00, 0x00, 0x01})
	require.ErrorIs(t, err, errAllocatorClosed)
}

// TestLabelValue: valid values pass, long clean values are cut to 32 chars, and
// other bad values are hashed.
func TestLabelValue(t *testing.T) {
	fullHex := "bf3df5c6a1e2d3c4b5a6978877665544bf3df5c6a1e2d3c4b5a6978877665544" // 64 hex, like a CRI container ID
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "valid passes through", in: "abc-123", want: "abc-123"},
		{name: "empty passes through", in: "", want: ""},
		{name: "over-long clean value truncates to the producer prefix", in: fullHex, want: fullHex[:32]},
		{name: "invalid characters hash", in: "not/a/label!", want: labelValue("not/a/label!")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := labelValue(tc.in)
			require.Equal(t, tc.want, got)
			require.LessOrEqual(t, len(got), 63)
		})
	}
	// The hashed form is stable and distinct from the input.
	h := labelValue("not/a/label!")
	require.Equal(t, h, labelValue("not/a/label!"))
	require.Len(t, h, 32)
	require.NotContains(t, h, "/")
}

// TestTunnelPublisherSharedV4Pool: tenants on one relay get different /32s
// because the shared leaser gives their slots different /24s.
func TestTunnelPublisherSharedV4Pool(t *testing.T) {
	ctx := context.Background()
	leaser := ipalloc.NewLocalSlotLeaser()

	connect := func(netID tunnet.NetworkID, id string) (v6, v4 netip.Prefix) {
		c := fake.NewClientBuilder().
			WithScheme(publisherScheme(t)).
			WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
			Build()
		p := NewTunnelPublisher(c, stubRelay{name: "relay-0"}, leaser, vni.NewVNIAllocator())
		t.Cleanup(func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			p.ReleaseAll(stopCtx)
		})
		p.SetNetworkID("corp", netID)
		conn := &fakeConn{id: id, network: "corp"}
		require.NoError(t, p.OnConnect(ctx, id, id, conn))
		require.Len(t, conn.addresses, 2, "connect must carry both families")
		return netip.MustParsePrefix(conn.addresses[0]), netip.MustParsePrefix(conn.addresses[1])
	}

	v6a, v4a := connect(tunnet.NetworkID{0x00, 0x00, 0x01}, "conn-tenant-a")
	v6b, v4b := connect(tunnet.NetworkID{0x00, 0x00, 0x02}, "conn-tenant-b")

	slotOf := func(p netip.Prefix) uint16 {
		b := p.Addr().As16()
		return uint16(b[9])<<8 | uint16(b[10])
	}
	require.Equal(t, slotOf(v6a), slotOf(v6b),
		"precondition: both tenants must hold the same slot id for this to test anything")
	require.NotEqual(t, v4a.Addr(), v4b.Addr(), "two tenants were handed the same /32")
}

// TestTunnelPublisherSlowWriteDoesNotDelayOthers: a hung create does not hold
// back other connections, and its ID gets no second write.
func TestTunnelPublisherSlowWriteDoesNotDelayOthers(t *testing.T) {
	ctx := context.Background()
	slowStarted := make(chan struct{})
	release := make(chan struct{})
	var slowCreates atomic.Int32
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if obj.GetName() == "conn-slow" {
					if slowCreates.Add(1) == 1 {
						close(slowStarted)
					}
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		Build()
	p, _ := newPublisherWithClient(t, c)

	require.NoError(t, p.OnConnect(ctx, "agent-slow", "agent-slow", &fakeConn{id: "conn-slow", network: "corp"}))
	select {
	case <-slowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("slow create did not start")
	}

	fast := make([]string, 2*syncParallelism)
	for i := range fast {
		fast[i] = fmt.Sprintf("conn-fast-%d", i)
		require.NoError(t, p.OnConnect(ctx, "agent-fast", "agent-fast", &fakeConn{id: fast[i], network: "corp"}))
	}
	require.Eventually(t, func() bool {
		for _, id := range fast {
			if !tunnelExists(t, c, id) {
				return false
			}
		}
		return true
	}, 2*time.Second, 5*time.Millisecond, "a slow create held back the other Tunnels")

	retryNow(p)
	require.Never(t, func() bool { return slowCreates.Load() > 1 }, 200*time.Millisecond, 10*time.Millisecond,
		"a second write started for an ID with a write in flight")
	require.False(t, tunnelExists(t, c, "conn-slow"))

	close(release)
	settle(t, p)
	require.True(t, tunnelExists(t, c, "conn-slow"))
	require.EqualValues(t, 1, slowCreates.Load())
}

// TestTunnelPublisherLimitsWritesInFlight covers the write limit: with every
// create blocked, no more than syncParallelism run at once.
func TestTunnelPublisherLimitsWritesInFlight(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	var inFlight, maxInFlight atomic.Int32
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithStatusSubresource(&vpcv1alpha1.Tunnel{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				n := inFlight.Add(1)
				defer inFlight.Add(-1)
				for m := maxInFlight.Load(); n > m && !maxInFlight.CompareAndSwap(m, n); m = maxInFlight.Load() {
				}
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		Build()
	p, _ := newPublisherWithClient(t, c)

	ids := make([]string, syncParallelism+4)
	for i := range ids {
		ids[i] = fmt.Sprintf("conn-%d", i)
		require.NoError(t, p.OnConnect(ctx, "agent", "agent", &fakeConn{id: ids[i], network: "corp"}))
	}
	require.Eventually(t, func() bool { return inFlight.Load() == syncParallelism },
		2*time.Second, 5*time.Millisecond, "writes did not reach the limit")
	require.Never(t, func() bool { return maxInFlight.Load() > syncParallelism },
		200*time.Millisecond, 10*time.Millisecond, "more writes than the limit ran at once")

	close(release)
	settle(t, p)
	for _, id := range ids {
		require.True(t, tunnelExists(t, c, id), "Tunnel %s was not written", id)
	}
}

// TestTunnelPublisherAssignAddress: v2 attachments get one /96 each from the
// held slots, with no apiserver call and no /32.
func TestTunnelPublisherAssignAddress(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().
		WithScheme(publisherScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				return apierrors.NewServiceUnavailable("project apiserver is down")
			},
		}).
		Build()
	p, netID := newPublisherWithClient(t, c)

	seen := make(map[netip.Prefix]bool)
	releases := make([]func(), 0, 3)
	for range 3 {
		v6, release, err := p.AssignAddress(ctx, netID)
		require.NoError(t, err)
		require.Equal(t, 96, v6.Bits())
		require.True(t, tunnet.NetworkPrefix(netID).Contains(v6.Addr()), "address %s is not in the network", v6)
		require.False(t, seen[v6], "address %s was given twice", v6)
		seen[v6] = true
		releases = append(releases, release)
	}

	// A v1 connection gets the first /32 of the slot.
	conn := &fakeConn{id: "conn-a", network: "corp"}
	require.NoError(t, p.OnConnect(ctx, "agent", "agent", conn))
	require.Len(t, conn.addresses, 2)
	require.Equal(t, byte(0), netip.MustParsePrefix(conn.addresses[1]).Addr().As4()[3], "v4 = %s", conn.addresses[1])

	// A second release of one /96 must not free another user's /96.
	releases[0]()
	releases[0]()
	again, _, err := p.AssignAddress(ctx, netID)
	require.NoError(t, err)
	require.True(t, seen[again], "a freed /96 was not used again")
	next, _, err := p.AssignAddress(ctx, netID)
	require.NoError(t, err)
	require.NotEqual(t, again, next)
	require.NotEqual(t, conn.overlay, next.String())
}
