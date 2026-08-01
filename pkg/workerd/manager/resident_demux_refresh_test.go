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
// The serving choice reads spec.liveRevision off the Service. A rollback
// repoints at an existing revision, so it mints nothing and fires no
// ServiceRevision event. Watching Service and mapping it to the same
// tenant-wide refresh key makes the pin reach the demux immediately.
func TestResidentReconciler_PinTakesEffectWithoutARevisionEvent(t *testing.T) {
	svc := &computev1alpha1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api"}}
	r, c := newResidentReconciler(t, &fakeResident{}, okFetcher(),
		svc, revisionAt("api-v1", "api", "sha256:1", 100), revisionAt("api-v2", "api", "sha256:2", 200))

	// Drive the revision events; with no pin the newest revision wins.
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

	// The Service watch coalesces that write into the tenant refresh
	// request. Reconciling it must republish the demux honoring the pin.
	if _, err := reconcileRevision(t, r, residentControllerName); err != nil {
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
	if _, err := reconcileRevision(t, r, residentControllerName); err != nil {
		t.Fatalf("demux refresh after un-pin: %v", err)
	}
	if got := liveRevision(t, r, "api"); got != "api-v2" {
		t.Errorf("after un-pinning, liveRevision = %q, want api-v2", got)
	}
}

// TestResidentReconciler_DemuxRefreshWarmsExistingServices covers the
// engage-time recovery path: a cold store plus already-existing revisions must
// end with every service represented in the demux, without relying on each
// revision's individual event.
func TestResidentReconciler_DemuxRefreshWarmsExistingServices(t *testing.T) {
	cases := []struct {
		name string
		objs []client.Object
		want map[string]string
	}{
		{
			name: "one existing service",
			objs: []client.Object{
				&computev1alpha1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api"}},
				revisionAt("api-v1", "api", "sha256:1", 100),
			},
			want: map[string]string{"api": "api-v1"},
		},
		{
			name: "every service and pinned revision",
			objs: []client.Object{
				&computev1alpha1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "api"},
					Spec:       computev1alpha1.ServiceSpec{LiveRevision: "api-v1"},
				},
				&computev1alpha1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web"}},
				revisionAt("api-v1", "api", "sha256:1", 100),
				revisionAt("api-v2", "api", "sha256:2", 200),
				revisionAt("web-v1", "web", "sha256:3", 300),
			},
			want: map[string]string{"api": "api-v1", "web": "web-v1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resident := &fakeResident{}
			r, _ := newResidentReconciler(t, resident, okFetcher(), tc.objs...)

			result, err := reconcileRevision(t, r, residentControllerName)
			if err != nil {
				t.Fatalf("demux refresh: %v", err)
			}
			if result.RequeueAfter != demuxResyncInterval {
				t.Errorf("RequeueAfter = %v, want periodic %v", result.RequeueAfter, demuxResyncInterval)
			}
			if got := resident.ensured(); got != 1 {
				t.Errorf("EnsureResident calls = %d, want 1", got)
			}
			for service, revision := range tc.want {
				if got := liveRevision(t, r, service); got != revision {
					t.Errorf("liveRevision(%s) = %q, want %q", service, got, revision)
				}
				if !r.store.cached(demuxID(service, revision)) {
					t.Errorf("%s revision %q was not warmed", service, revision)
				}
			}
		})
	}
}

// TestEnqueueResidentRefresh checks that every resident input funnels through one
// tenant-wide workqueue key.
func TestEnqueueResidentRefresh(t *testing.T) {
	cases := []struct {
		name string
		obj  client.Object
	}{
		{
			name: "service event",
			obj:  &computev1alpha1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api"}},
		},
		{
			name: "revision event",
			obj:  revision("api-v1", "api", "sha256:1"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs := enqueueResidentRefresh(context.Background(), tc.obj)
			if len(reqs) != 1 {
				t.Fatalf("got %d requests, want 1: %v", len(reqs), reqs)
			}
			if got := reqs[0].Name; got != residentControllerName {
				t.Errorf("request name = %q, want %q", got, residentControllerName)
			}
			if reqs[0].Namespace != "" {
				t.Errorf("request namespace = %q, want cluster-scoped singleton", reqs[0].Namespace)
			}
		})
	}
}
