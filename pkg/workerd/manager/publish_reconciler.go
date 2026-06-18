// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

var _ reconcile.Reconciler = &PublishReconciler{}

// PublishReconciler keeps the backplane's view of workerd routing current. It
// watches compute Services and, on any change, rebuilds the service->live-rev
// demux map and publishes it (with the resident socket) to the co-located
// backplane over the private channel (APO-796 directive: the backplane learns
// the resident endpoint and routing from the manager, never the customer API).
type PublishReconciler struct {
	client.Client
	publisher      Publisher
	residentSocket string
	projectID      string
}

// NewPublishReconciler returns a publish reconciler that advertises
// residentSocket and the project-qualified live-revision map via publisher.
func NewPublishReconciler(c client.Client, publisher Publisher, residentSocket, projectID string) *PublishReconciler {
	return &PublishReconciler{Client: c, publisher: publisher, residentSocket: residentSocket, projectID: projectID}
}

// Reconcile rebuilds and republishes the full snapshot on any Service change.
// It publishes the whole map (not a delta) so the backplane state is always a
// faithful mirror, and a missed event self-heals on the next reconcile.
func (r *PublishReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)

	services := &computev1alpha1.ServiceList{}
	if err := r.List(ctx, services); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing services: %w", err)
	}

	// Key the demux map by "<project>:<service>" so the backplane (which serves
	// many projects on the shared Envoy) never collides two projects' same-named
	// services; the backplane builds the header as key + ":" + liveRevision.
	demux := make(map[string]string)
	for i := range services.Items {
		svc := &services.Items[i]
		if svc.Status.LiveRevision != "" {
			demux[serviceDemuxKey(r.projectID, svc.Name)] = svc.Status.LiveRevision
		}
	}

	if err := r.publisher.Publish(ctx, PublishSnapshot{
		ResidentSocket: r.residentSocket,
		Demux:          demux,
	}); err != nil {
		// Surface so controller-runtime retries with backoff; a stale backplane
		// must converge.
		return ctrl.Result{}, fmt.Errorf("publishing routing snapshot: %w", err)
	}
	log.Info("Published workerd routing to backplane", "services", len(demux))
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler with the manager.
func (r *PublishReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("compute-publish").
		For(&computev1alpha1.Service{}).
		Complete(r)
}
