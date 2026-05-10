// Predicates used by the GatewayClass reconciler's Builder. The reconciler
// is a single fat reconciler that re-translates all Gateway-API objects on
// every queue pull, so the predicate choice directly governs the controller's
// steady-state reconcile rate.
//
// Background: the reconciler writes status conditions back to N Gateways and
// M Routes on every translation cycle. Every status write bumps the target's
// resourceVersion. With predicate.ResourceVersionChangedPredicate{} on every
// watch, each of those writes re-enqueues this controller, which translates
// again, which writes status again — a self-amplifying loop that drives the
// observed ~30 reconciles/sec/apiserver in steady state.
//
// generationOrDeletion fires only on:
//   - spec changes (.metadata.generation bumps), which is what we actually
//     need to retranslate, and
//   - the deletion-request Update (.metadata.deletionTimestamp set from
//     zero), which is needed so finalizer cleanup paths run. Object types
//     with finalizers do not go through Delete-event paths on the first
//     delete — they go through Update with deletionTimestamp set, and only
//     produce a Delete event after the controller clears its finalizer.
//
// What this filters out (intentionally):
//   - The controller's own status writes (no generation change).
//   - Server-side managedFields churn on kubectl/Argo applies.
//   - Annotation/label edits that don't affect translation.
//
// What this does NOT cover:
//   - corev1.Secret has no .spec/.status split; .metadata.generation is
//     never bumped. Use predicate.ResourceVersionChangedPredicate{} for
//     Secrets — the controller does not write Secrets, so there is no
//     amplification loop to worry about.
//   - extensionsv1alpha2.EdgeFunction gates translation on
//     Status.LiveRevision (see the field indexer in SetupWithManager).
//     Status changes there MUST retrigger; use edgeFunctionRetrigger.
package gateway

import (
	"bytes"
	"maps"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

// generationOrDeletion fires on spec changes (Generation bump) and on the
// initial deletionTimestamp-set Update. Default Create/Delete/Generic paths
// (true) are retained — only Update events are filtered.
var generationOrDeletion = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		if e.ObjectOld == nil || e.ObjectNew == nil {
			return false
		}
		if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
			return true
		}
		// Deletion-request: deletionTimestamp transitions from zero to set.
		// Generation does not bump on this transition, so it must be checked
		// explicitly or finalizer-bearing objects will leak.
		return e.ObjectOld.GetDeletionTimestamp().IsZero() &&
			!e.ObjectNew.GetDeletionTimestamp().IsZero()
	},
}

// edgeFunctionRetrigger is generationOrDeletion plus a clause for
// Status.LiveRevision: when an EdgeFunction publishes a new live revision
// the translator must re-emit xDS so the new revision is routed to. The
// field indexer in SetupWithManager keys off Status.LiveRevision != "", so
// without this clause the indexer view goes stale.
var edgeFunctionRetrigger = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldEF, ok := e.ObjectOld.(*extensionsv1alpha2.EdgeFunction)
		if !ok {
			return false
		}
		newEF, ok := e.ObjectNew.(*extensionsv1alpha2.EdgeFunction)
		if !ok {
			return false
		}
		if oldEF.Generation != newEF.Generation {
			return true
		}
		if oldEF.Status.LiveRevision != newEF.Status.LiveRevision {
			return true
		}
		return oldEF.DeletionTimestamp.IsZero() && !newEF.DeletionTimestamp.IsZero()
	},
}

// secretDataChanged is used in place of ResourceVersionChangedPredicate
// where we want to ignore managedFields/annotation churn but still react
// to the actual secret payload changing or to deletion. corev1.Secret has
// no .spec, so this is the moral equivalent of "generation bump" for it.
//
// Currently unused: callers that watch Secret keep
// ResourceVersionChangedPredicate{} (this controller does not write Secrets,
// so the amplification risk is zero and the simpler predicate is fine).
// Kept here in case a future caller wants the tighter filter.
var secretDataChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldS, ok := e.ObjectOld.(*corev1.Secret)
		if !ok {
			return false
		}
		newS, ok := e.ObjectNew.(*corev1.Secret)
		if !ok {
			return false
		}
		if !maps.EqualFunc(oldS.Data, newS.Data, bytes.Equal) {
			return true
		}
		return oldS.DeletionTimestamp.IsZero() && !newS.DeletionTimestamp.IsZero()
	},
}
