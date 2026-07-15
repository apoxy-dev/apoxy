// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// newEgressFakeClient is newFakeClient plus the egress kinds' status
// subresources.
func newEgressFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(
			&computev1alpha1.Service{}, &computev1alpha1.ServiceRevision{},
			&computev1alpha1.EgressGateway{}, &computev1alpha1.EgressRoute{},
		).
		WithObjects(objs...).
		Build()
}

// egressService builds a Service fixture with the given template egress and,
// when live is non-empty, a serving revision recorded in status.
func egressService(name, live string, egress *computev1alpha1.ServiceEgress) *computev1alpha1.Service {
	svc := &computev1alpha1.Service{ObjectMeta: metav1.ObjectMeta{Name: name}}
	svc.Spec.Template.Spec.Egress = egress
	svc.Status.LiveRevision = live
	return svc
}

// egressRevision builds a ServiceRevision fixture carrying an egress block.
func egressRevision(name string, egress *computev1alpha1.ServiceEgress) *computev1alpha1.ServiceRevision {
	rev := revision(name, "api", "sha256:a")
	rev.Spec.Egress = egress
	return rev
}

func TestEgressStatusReconciler(t *testing.T) {
	ctx := context.Background()
	fullPass := egressFullPassRequest

	t.Run("writes the full status contract", func(t *testing.T) {
		gw := egw("locked-down", computev1alpha1.EgressPolicyDenyAll,
			computev1alpha1.EgressListener{Name: "https", Protocol: computev1alpha1.EgressProtocolHTTPS})
		route := eroute("allow-openai", "locked-down", "https", computev1alpha1.EgressRouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.openai.com"},
		})
		c := newEgressFakeClient(t,
			egressService("api", "", &computev1alpha1.ServiceEgress{GatewayRef: "locked-down"}),
			&gw, &route,
		)

		if _, err := NewEgressStatusReconciler(c).Reconcile(ctx, fullPass); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}

		var svc computev1alpha1.Service
		if err := c.Get(ctx, types.NamespacedName{Name: "api"}, &svc); err != nil {
			t.Fatalf("Get service: %v", err)
		}
		cond := meta.FindStatusCondition(svc.Status.Conditions, computev1alpha1.ConditionEgressReady)
		if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != computev1alpha1.EgressReadyReasonGatewayNotReady {
			t.Errorf("EgressReady = %+v; want False/GatewayNotReady (gateway has no data plane)", cond)
		}

		var gotGw computev1alpha1.EgressGateway
		if err := c.Get(ctx, types.NamespacedName{Name: "locked-down"}, &gotGw); err != nil {
			t.Fatalf("Get gateway: %v", err)
		}
		ready := meta.FindStatusCondition(gotGw.Status.Conditions, computev1alpha1.EgressGatewayConditionReady)
		if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != computev1alpha1.EgressGatewayReasonListenersPending {
			t.Errorf("gateway Ready = %+v; want False/ListenersPending", ready)
		}
		if len(gotGw.Status.Listeners) != 1 || gotGw.Status.Listeners[0].Name != "https" ||
			gotGw.Status.Listeners[0].AttachedRoutes != 1 {
			t.Errorf("gateway listeners = %+v; want https with attachedRoutes=1", gotGw.Status.Listeners)
		}

		var gotRoute computev1alpha1.EgressRoute
		if err := c.Get(ctx, types.NamespacedName{Name: "allow-openai"}, &gotRoute); err != nil {
			t.Fatalf("Get route: %v", err)
		}
		if len(gotRoute.Status.Parents) != 1 ||
			gotRoute.Status.Parents[0].ControllerName != computev1alpha1.EgressControllerName ||
			len(gotRoute.Status.Parents[0].Conditions) != 1 ||
			gotRoute.Status.Parents[0].Conditions[0].Status != metav1.ConditionTrue {
			t.Errorf("route parents = %+v; want one accepted parent", gotRoute.Status.Parents)
		}
	})

	t.Run("live revision's egress governs over the template", func(t *testing.T) {
		// The template asks for a gateway, but the serving revision was minted
		// with disabled egress — the SERVING config wins.
		c := newEgressFakeClient(t,
			egressService("api", "api-r1", &computev1alpha1.ServiceEgress{GatewayRef: "missing"}),
			egressRevision("api-r1", &computev1alpha1.ServiceEgress{Disabled: true}),
		)
		if _, err := NewEgressStatusReconciler(c).Reconcile(ctx, fullPass); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		var svc computev1alpha1.Service
		if err := c.Get(ctx, types.NamespacedName{Name: "api"}, &svc); err != nil {
			t.Fatalf("Get service: %v", err)
		}
		cond := meta.FindStatusCondition(svc.Status.Conditions, computev1alpha1.ConditionEgressReady)
		if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != computev1alpha1.EgressReadyReasonDisabled {
			t.Errorf("EgressReady = %+v; want True/Disabled from the live revision", cond)
		}
	})

	t.Run("repeat reconcile is a no-op (LastTransitionTime stable)", func(t *testing.T) {
		c := newEgressFakeClient(t, egressService("api", "", nil))
		r := NewEgressStatusReconciler(c)
		if _, err := r.Reconcile(ctx, fullPass); err != nil {
			t.Fatalf("first Reconcile: %v", err)
		}
		var first computev1alpha1.Service
		if err := c.Get(ctx, types.NamespacedName{Name: "api"}, &first); err != nil {
			t.Fatalf("Get: %v", err)
		}
		firstCond := meta.FindStatusCondition(first.Status.Conditions, computev1alpha1.ConditionEgressReady)
		if firstCond == nil || firstCond.Reason != computev1alpha1.EgressReadyReasonApplied {
			t.Fatalf("EgressReady = %+v; want True/Applied (implicit default)", firstCond)
		}

		time.Sleep(1100 * time.Millisecond) // metav1.Time has second granularity
		if _, err := r.Reconcile(ctx, fullPass); err != nil {
			t.Fatalf("second Reconcile: %v", err)
		}
		var second computev1alpha1.Service
		if err := c.Get(ctx, types.NamespacedName{Name: "api"}, &second); err != nil {
			t.Fatalf("Get: %v", err)
		}
		secondCond := meta.FindStatusCondition(second.Status.Conditions, computev1alpha1.ConditionEgressReady)
		if !secondCond.LastTransitionTime.Equal(&firstCond.LastTransitionTime) {
			t.Errorf("LastTransitionTime moved on a no-op reconcile: %v -> %v",
				firstCond.LastTransitionTime, secondCond.LastTransitionTime)
		}
	})
}

// scriptedApplier is a host.EgressApplier whose next response can report a
// newer retained generation (the stale-push path).
type scriptedApplier struct {
	mu       sync.Mutex
	applies  []host.EgressApply
	retained uint64 // when > incoming generation, reported instead
}

func (f *scriptedApplier) ApplyEgress(apply host.EgressApply) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retained > apply.Generation {
		return f.retained, nil
	}
	f.retained = apply.Generation
	f.applies = append(f.applies, apply)
	return apply.Generation, nil
}

func (f *scriptedApplier) applied() []host.EgressApply {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]host.EgressApply(nil), f.applies...)
}

// startEgressServerAt binds an EgressControlServer on the tenant's
// deterministic socket under dir (the path the pusher will dial).
func startEgressServerAt(t *testing.T, dir, tenant string, applier host.EgressApplier) {
	t.Helper()
	srv := NewEgressControlServer(tenant, applier)
	if err := srv.Listen(EgressSocketPath(dir, tenant)); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("egress server did not shut down")
		}
	})
}

func TestEgressPusher(t *testing.T) {
	ctx := context.Background()
	const tenant = "11111111-2222-3333-4444-555555555555"

	liveObjects := func() []client.Object {
		gw := readyGw(egw("locked-down", computev1alpha1.EgressPolicyDenyAll,
			computev1alpha1.EgressListener{Name: "https", Protocol: computev1alpha1.EgressProtocolHTTPS}), "10.0.0.1:8093")
		return []client.Object{
			egressService("api", "api-r1", nil),
			egressRevision("api-r1", &computev1alpha1.ServiceEgress{GatewayRef: "locked-down"}),
			egressService("web", "web-r1", nil),
			egressRevision("web-r1", nil),
			egressService("unminted", "", &computev1alpha1.ServiceEgress{Disabled: true}),
			&gw,
		}
	}

	t.Run("pushes the whole live state over the socket", func(t *testing.T) {
		dir := shortSockDir(t)
		applier := &scriptedApplier{}
		startEgressServerAt(t, dir, tenant, applier)

		p := NewEgressPusher(dir)
		if _, err := p.ReconcileWithClient(ctx, tenant, newEgressFakeClient(t, liveObjects()...), ctrl.Request{}); err != nil {
			t.Fatalf("ReconcileWithClient: %v", err)
		}

		applies := applier.applied()
		if len(applies) != 1 {
			t.Fatalf("applier saw %d applies; want 1", len(applies))
		}
		got := applies[0].Services
		// Only live Services, sorted; "unminted" has no serving worker.
		if len(got) != 2 || got[0].Service != "api" || got[1].Service != "web" {
			t.Fatalf("pushed services = %+v; want [api web]", got)
		}
		if got[0].Policy == nil || !got[0].Policy.DefaultDeny ||
			len(got[0].Backends) != 1 || got[0].Backends[0].Addr != "10.0.0.1:8093" {
			t.Errorf("api plane = %+v; want deny-all with the gateway backend", got[0])
		}
		if got[1].Policy != nil {
			t.Errorf("web plane = %+v; want nil policy (implicit default)", got[1])
		}
	})

	t.Run("nothing live pushes nothing", func(t *testing.T) {
		dir := shortSockDir(t)
		applier := &scriptedApplier{}
		startEgressServerAt(t, dir, tenant, applier)

		p := NewEgressPusher(dir)
		c := newEgressFakeClient(t, egressService("unminted", "", nil))
		if _, err := p.ReconcileWithClient(ctx, tenant, c, ctrl.Request{}); err != nil {
			t.Fatalf("ReconcileWithClient: %v", err)
		}
		if got := applier.applied(); len(got) != 0 {
			t.Errorf("applier saw %+v; want no pushes", got)
		}
	})

	t.Run("resident not up requeues instead of erroring", func(t *testing.T) {
		p := NewEgressPusher(shortSockDir(t)) // no server bound
		res, err := p.ReconcileWithClient(ctx, tenant, newEgressFakeClient(t, liveObjects()...), ctrl.Request{})
		if err != nil {
			t.Fatalf("ReconcileWithClient: %v", err)
		}
		if res.RequeueAfter != egressPushRetryAfter {
			t.Errorf("RequeueAfter = %v; want %v", res.RequeueAfter, egressPushRetryAfter)
		}
	})

	t.Run("generations increase and stale responses self-heal", func(t *testing.T) {
		dir := shortSockDir(t)
		applier := &scriptedApplier{retained: 100} // resident retains a far-newer generation
		startEgressServerAt(t, dir, tenant, applier)

		p := NewEgressPusher(dir)
		c := newEgressFakeClient(t, liveObjects()...)
		if _, err := p.ReconcileWithClient(ctx, tenant, c, ctrl.Request{}); err != nil {
			t.Fatalf("ReconcileWithClient: %v", err)
		}
		applies := applier.applied()
		if len(applies) != 1 || applies[0].Generation != 101 {
			t.Fatalf("applies = %+v; want one re-push at generation 101", applies)
		}
		if _, err := p.ReconcileWithClient(ctx, tenant, c, ctrl.Request{}); err != nil {
			t.Fatalf("second ReconcileWithClient: %v", err)
		}
		applies = applier.applied()
		if len(applies) != 2 || applies[1].Generation != 102 {
			t.Errorf("applies = %+v; want the second push at generation 102", applies)
		}
	})
}
