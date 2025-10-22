// Package extensions implements extensions controllers.
package extensions

import (
	"context"
	goerrors "errors"
	"fmt"
	"time"

	"go.temporal.io/api/serviceerror"
	tclient "go.temporal.io/sdk/client"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/apiserver/ingest"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

var _ reconcile.Reconciler = &EdgeFunctionReconciler{}

// EdgeFunctionReconciler reconciles an EdgeFunction object.
type EdgeFunctionReconciler struct {
	client.Client
	scheme *runtime.Scheme
	tc     tclient.Client
}

// NewEdgeFunctionReconciler returns a new reconcile.Reconciler.
func NewEdgeFunctionReconciler(
	c client.Client,
	s *runtime.Scheme,
	tc tclient.Client,
) *EdgeFunctionReconciler {
	return &EdgeFunctionReconciler{
		Client: c,
		scheme: s,
		tc:     tc,
	}
}

func hasIngestCondition(obj *extensionsv1alpha2.EdgeFunctionRevision) bool {
	for _, c := range obj.Status.Conditions {
		if c.Type == "Ingest" && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

func (r *EdgeFunctionReconciler) startIngest(
	ctx context.Context,
	obj *extensionsv1alpha2.EdgeFunction,
) (*extensionsv1alpha2.EdgeFunctionRevision, error) {
	tmplHash := EdgeFunctionHash(obj.Spec.Template)

	log := clog.FromContext(ctx, "Hash", tmplHash)

	revName := fmt.Sprintf("%s-%s", obj.Name, tmplHash)
	rev := &extensionsv1alpha2.EdgeFunctionRevision{}
	if err := r.Get(ctx, client.ObjectKey{Name: revName}, rev); err != nil && !errors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get EdgeFunctionRevision: %w", err)
	} else if errors.IsNotFound(err) {
		log.Info("EdgeFunctionRevision not found, starting ingest workflow")

		rev = &extensionsv1alpha2.EdgeFunctionRevision{
			ObjectMeta: metav1.ObjectMeta{
				Name: revName,
				Labels: map[string]string{
					"extensions.apoxy.dev/edgefunction": obj.Name,
				},
				Annotations: map[string]string{},
			},
			Spec: *obj.Spec.Template.DeepCopy(),
		}
		for k, v := range obj.Labels {
			rev.Labels[k] = v
		}
		for k, v := range obj.Annotations {
			rev.Annotations[k] = v
		}
		if err := controllerutil.SetControllerReference(obj, rev, r.scheme); err != nil {
			return nil, fmt.Errorf("failed to set controller reference: %w", err)
		}
		if err := r.Create(ctx, rev); err != nil {
			return nil, fmt.Errorf("failed to create EdgeFunctionRevision: %w", err)
		}
	} else if err == nil && hasIngestCondition(rev) {
		log.Info("Found existing EdgeFunctionRevision, skipping ingest workflow")
		return rev, nil
	}

	log.Info("Starting ingest workflow")

	wOpts := tclient.StartWorkflowOptions{
		ID:                       revName,
		TaskQueue:                ingest.EdgeFunctionIngestQueue,
		WorkflowExecutionTimeout: 10 * time.Minute,
	}
	in := &ingest.EdgeFunctionIngestParams{
		Obj: rev.DeepCopy(),
	}
	if _, err := r.tc.ExecuteWorkflow(ctx, wOpts, ingest.EdgeFunctionIngestWorkflow, in); err != nil {
		return nil, fmt.Errorf("failed to start ingest workflow: %w", err)
	}
	return rev, nil
}

func (r *EdgeFunctionReconciler) cancelIngest(ctx context.Context, obj *extensionsv1alpha2.EdgeFunction) error {
	tmplHash := EdgeFunctionHash(obj.Spec.Template)
	revName := fmt.Sprintf("%s-%s", obj.Name, tmplHash)
	log := clog.FromContext(ctx, "Revision", revName)

	log.Info("Cancelling ingest workflow")

	if err := r.tc.CancelWorkflow(ctx, revName, ""); err != nil {
		var serviceErr *serviceerror.NotFound
		if !goerrors.As(err, &serviceErr) {
			return fmt.Errorf("failed to describe workflow execution: %w", err)
		}
		log.Info("Workflow is not found, nothing to cancel")
	}

	return nil
}

func hasReadyCondition(rev *extensionsv1alpha2.EdgeFunctionRevision) bool {
	for _, c := range rev.Status.Conditions {
		if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// Reconcile implements reconcile.Reconciler.
func (r *EdgeFunctionReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	f := &extensionsv1alpha2.EdgeFunction{}
	err := r.Get(ctx, request.NamespacedName, f)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get EdgeFunction: %w", err)
	}

	log := clog.FromContext(ctx, "name", f.Name)
	log.Info("Reconciling EdgeFunction")

	if !f.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("EdgeFunction is being deleted")
		if err := r.cancelIngest(ctx, f); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cancel ingest workflow: %w", err)
		}
		return ctrl.Result{}, nil
	}

	if rev, err := r.startIngest(clog.IntoContext(ctx, log), f); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to start ingest workflow: %w", err)
	} else if rev != nil {
		if hasReadyCondition(rev) {
			// Found existing revision. Check if it has Ready condition (ingested successfully)
			// and if yes, set it to live.
			log.Info("Found existing EdgeFunction revision, setting to live", "Revision", rev)

			f.Status.LiveRevision = rev.Name

			if err := r.Status().Update(ctx, f); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update EdgeFunction: %w", err)
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *EdgeFunctionReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("edgefunction-ingest").
		For(&extensionsv1alpha2.EdgeFunction{}).
		Owns(&extensionsv1alpha2.EdgeFunctionRevision{}).
		Complete(r)
}
