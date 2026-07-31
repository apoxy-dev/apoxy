// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// TestResidentReconciler_PinTakesEffectWithoutARevisionEvent is the regression
// test for rollback silently not taking.
//
// The serving choice reads spec.liveRevision off the SERVICE, but the
// controller is keyed on ServiceRevisions. A rollback repoints at an EXISTING
// revision, so it mints nothing and fires no ServiceRevision event — the demux
// was never recomputed and the node kept serving the newest revision while
// status.liveRevision reported the pin had taken. Service events now coalesce
// into the synthetic DemuxRefreshRequestName request, which lands in
// Reconcile's not-found branch and recomputes the demux.
func TestResidentReconciler_PinTakesEffectWithoutARevisionEvent(t *testing.T) {
	svc := &computev1alpha1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api"}}
	r, c := newResidentReconciler(t, &fakeResident{}, okFetcher(),
		svc, revisionAt("api-v1", "api", "sha256:1", 100), revisionAt("api-v2", "api", "sha256:2", 200))

	// Warm both; with no pin the newest wins.
	if _, err := reconcileRevision(t, r, "api-v1"); err != nil {
		t.Fatalf("v1: %v", err)
	}
	if _, err := reconcileRevision(t, r, "api-v2"); err != nil {
		t.Fatalf("v2: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v2" {
		t.Fatalf("precondition: liveRevision = %q, want api-v2", got)
	}

	// Roll back by pinning the older revision — the only API write a rollback
	// makes. No revision is created, updated, or deleted.
	live := &computev1alpha1.Service{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "api"}, live); err != nil {
		t.Fatalf("get service: %v", err)
	}
	live.Spec.LiveRevision = "api-v1"
	if err := c.Update(context.Background(), live); err != nil {
		t.Fatalf("pinning liveRevision: %v", err)
	}

	// The Service watch coalesces that write into the synthetic refresh
	// request. Reconciling it must republish the demux honoring the pin.
	if _, err := reconcileRevision(t, r, DemuxRefreshRequestName); err != nil {
		t.Fatalf("demux refresh: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v1" {
		t.Errorf("after pinning and a demux refresh, liveRevision = %q, want api-v1 (rollback did not take)", got)
	}

	// Un-pinning is the same shape and must be equally live: back to newest.
	if err := c.Get(context.Background(), client.ObjectKey{Name: "api"}, live); err != nil {
		t.Fatalf("re-get service: %v", err)
	}
	live.Spec.LiveRevision = ""
	if err := c.Update(context.Background(), live); err != nil {
		t.Fatalf("un-pinning liveRevision: %v", err)
	}
	if _, err := reconcileRevision(t, r, DemuxRefreshRequestName); err != nil {
		t.Fatalf("demux refresh after un-pin: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v2" {
		t.Errorf("after un-pinning, liveRevision = %q, want api-v2", got)
	}
}

// TestResidentReconciler_DemuxRefreshWarmsNothing keeps the synthetic request
// cheap and safe: it must not be mistaken for a revision, so it neither warms
// nor touches the resident. Only refreshDemux runs.
func TestResidentReconciler_DemuxRefreshWarmsNothing(t *testing.T) {
	res := &fakeResident{}
	r, _ := newResidentReconciler(t, res, okFetcher(),
		&computev1alpha1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api"}},
		revision("api-v1", "api", "sha256:1"))

	if _, err := reconcileRevision(t, r, DemuxRefreshRequestName); err != nil {
		t.Fatalf("demux refresh: %v", err)
	}
	if got := res.ensured(); got != 0 {
		t.Errorf("EnsureResident called %d times for a demux refresh, want 0", got)
	}
	if got := liveRevision(t, r, "api"); got != "" {
		t.Errorf("demux refresh warmed %q; it must only republish what is already warm", got)
	}
}

// TestEnqueueDemuxRefresh checks the handler every Service event funnels
// through: any Service, one synthetic request.
func TestEnqueueDemuxRefresh(t *testing.T) {
	h := EnqueueDemuxRefresh()
	if h == nil {
		t.Fatal("EnqueueDemuxRefresh() = nil")
	}
	// The map func is what carries the behavior; exercise it directly through
	// the same shape the handler wraps.
	reqs := []string{}
	for _, name := range []string{"api", "other"} {
		for _, r := range mapDemuxRefresh(context.Background(), &computev1alpha1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		}) {
			reqs = append(reqs, r.Name)
		}
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want one per Service event: %v", len(reqs), reqs)
	}
	for _, got := range reqs {
		if got != DemuxRefreshRequestName {
			t.Errorf("request name = %q, want %q", got, DemuxRefreshRequestName)
		}
	}
}
