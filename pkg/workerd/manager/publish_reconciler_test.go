// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// fakePublisher records the last published snapshot.
type fakePublisher struct {
	last PublishSnapshot
	n    int
	err  error
}

func (f *fakePublisher) Publish(_ context.Context, snap PublishSnapshot) error {
	if f.err != nil {
		return f.err
	}
	f.last = snap
	f.n++
	return nil
}

func serviceWithLive(name, liveRev string) *computev1alpha1.Service {
	svc := &computev1alpha1.Service{ObjectMeta: metav1.ObjectMeta{Name: name}}
	svc.Status.LiveRevision = liveRev
	return svc
}

func TestPublishReconciler_PublishesDemuxAndSocket(t *testing.T) {
	c := newFakeClient(t,
		serviceWithLive("api", "api-r1"),
		serviceWithLive("web", "web-r3"),
		serviceWithLive("pending", ""), // no live revision yet -> excluded
	)
	pub := &fakePublisher{}
	r := NewPublishReconciler(c, pub, "/run/resident.in.sock", "proj")

	if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "api"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if pub.last.ResidentSocket != "/run/resident.in.sock" {
		t.Errorf("ResidentSocket = %q", pub.last.ResidentSocket)
	}
	// The demux map is keyed by the project-qualified service key "<project>:<service>".
	if got := pub.last.Demux; len(got) != 2 || got["proj:api"] != "api-r1" || got["proj:web"] != "web-r3" {
		t.Errorf("demux = %+v, want {proj:api:api-r1, proj:web:web-r3}", got)
	}
	if _, ok := pub.last.Demux["proj:pending"]; ok {
		t.Error("a service with no live revision must be excluded from the demux map")
	}
}

func TestPublishReconciler_PropagatesPublishError(t *testing.T) {
	c := newFakeClient(t, serviceWithLive("api", "api-r1"))
	r := NewPublishReconciler(c, &fakePublisher{err: fmt.Errorf("backplane down")}, "/s", "proj")
	if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "api"}}); err == nil {
		t.Fatal("want error when the backplane publish fails")
	}
}
