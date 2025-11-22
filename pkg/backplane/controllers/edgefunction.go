package controllers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/backplane/wasm/manifest"
	"github.com/apoxy-dev/apoxy/pkg/edgefunc"
)

const (
	edgeFuncRevsOwnerIndex = "edgeFuncRevsOwner"
)

var _ reconcile.Reconciler = &EdgeFunctionRevisionReconciler{}

// EdgeFunctionRevisionReconciler reconciles an EdgeFunctionRevision object
// representing an edge function executable.
type EdgeFunctionRevisionReconciler struct {
	client.Client

	replicaName   string
	apiserverHost string
	wasmStore     manifest.Store
	goStoreDir    string
	jsStoreDir    string
	edgeRuntime   edgefunc.Runtime
}

// NewEdgeFunctionRevisionReconciler returns a new reconcile.Reconciler.
func NewEdgeFunctionRevisionReconciler(
	c client.Client,
	replicaName string,
	apiserverHost string,
	wasmStore manifest.Store,
	goStoreDir string,
	jsStoreDir string,
	edgeRuntime edgefunc.Runtime,
) *EdgeFunctionRevisionReconciler {
	return &EdgeFunctionRevisionReconciler{
		Client:        c,
		replicaName:   replicaName,
		apiserverHost: apiserverHost,
		wasmStore:     wasmStore,
		goStoreDir:    goStoreDir,
		jsStoreDir:    jsStoreDir,
		edgeRuntime:   edgeRuntime,
	}
}

func (r *EdgeFunctionRevisionReconciler) downloadFuncData(
	ctx context.Context,
	fnType string,
	ref string,
) ([]byte, error) {
	log := clog.FromContext(ctx)

	resp, err := http.Get(fmt.Sprintf("http://%s/%s/%s", r.apiserverHost, fnType, ref))
	if err != nil {
		return nil, fmt.Errorf("failed to download edge function: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download edge function: %s", resp.Status)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read edge function data: %w", err)
	}

	log.Info("Downloaded EdgeFunction module", "size", len(data), "type", fnType, "ref", ref)

	return data, nil
}

func hasReadyCondition(conditions []metav1.Condition) bool {
	for _, condition := range conditions {
		if condition.Type == "Ready" && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

func (r *EdgeFunctionRevisionReconciler) reconileEdgeRuntime(
	ctx context.Context,
	ref string,
	runtimeSpec *extensionsv1alpha2.EdgeFunctionRuntime,
) error {
	log := clog.FromContext(ctx)

	esZipPath := filepath.Join(r.jsStoreDir, ref, "bin.eszip")
	if _, err := os.Stat(esZipPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("Js bundle already exists for ref")
	} else if os.IsNotExist(err) {
		jsBundle, err := r.downloadFuncData(clog.IntoContext(ctx, log), "js", ref)
		if err != nil {
			return fmt.Errorf("failed to download Js data: %w", err)
		}

		if err := os.MkdirAll(filepath.Join(r.jsStoreDir, ref), 0755); err != nil {
			return fmt.Errorf("failed to create Js directory: %w", err)
		}

		if err := os.WriteFile(filepath.Join(r.jsStoreDir, ref, "data"), jsBundle, 0644); err != nil {
			return fmt.Errorf("failed to write Js data: %w", err)
		}
		// Use symlink to prevent Envoy from loading the plugin while it's being written to.
		if err := os.Symlink("data", esZipPath); err != nil {
			return fmt.Errorf("failed to create Js symlink: %w", err)
		}
	}

	s, err := r.edgeRuntime.ExecStatus(ctx, ref)
	if err != nil && !errors.Is(err, edgefunc.ErrNotFound) {
		return fmt.Errorf("failed to get Edge Runtime status: %w", err)
	}

	log.Info("Edge Runtime status", "state", s.State)

	switch s.State {
	case edgefunc.StateRunning, edgefunc.StateCreated:
		log.Info("Edge Runtime is already running or created", "state", s.State)
		return nil
	case edgefunc.StateStopped:
		log.Info("Edge Runtime is stopped, starting it")
	}

	log.Info("Starting Edge Runtime")

	if err := r.edgeRuntime.Exec(ctx, ref, esZipPath, int(*runtimeSpec.Port)); err != nil {
		return fmt.Errorf("failed to start Edge Runtime: %w", err)
	}

	return nil
}

func (r *EdgeFunctionRevisionReconciler) maybeCleanupEdgeRuntime(ctx context.Context, ref string) (bool, error) {
	log := clog.FromContext(ctx, "Ref", ref)

	log.Info("Cleaning up Edge Runtime")

	if err := r.edgeRuntime.StopExec(ctx, ref); err != nil {
		log.Error(err, "Failed to stop Edge Runtime")
		return false, err
	}
	s, err := r.edgeRuntime.ExecStatus(ctx, ref)
	if err != nil {
		log.Error(err, "Failed to get Edge Runtime status")
		return false, err
	}

	switch s.State {
	case edgefunc.StateRunning, edgefunc.StateCreated:
		log.Info("Edge Runtime is still waiting for termination")
		return false, nil
	case edgefunc.StateStopped:
		log.Info("Edge Runtime is stopped, cleaning up")
	}

	if err := r.edgeRuntime.DeleteExec(ctx, ref); err != nil && !errors.Is(err, edgefunc.ErrNotFound) {
		log.Error(err, "Failed to delete Edge Runtime")
	} else if errors.Is(err, edgefunc.ErrNotFound) {
		log.Info("Edge Runtime not found, nothing to delete")
		return true, nil
	}

	log.Info("Edge Runtime deleted, cleaning up data")

	jsBundlePath := filepath.Join(r.jsStoreDir, ref, "data")
	if err := os.RemoveAll(jsBundlePath); err != nil {
		log.Error(err, "Failed to delete Js bundle")
	}

	log.Info("Edge Runtime cleaned up")

	return true, nil
}

// Reconcile implements reconcile.Reconciler.
func (r *EdgeFunctionRevisionReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)
	log.Info("Reconciling EdgeFunctionRevision")

	rev := &extensionsv1alpha2.EdgeFunctionRevision{}
	if err := r.Get(ctx, request.NamespacedName, rev); err != nil {
		log.Error(err, "Failed to get EdgeFunctionRevision")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	owner := metav1.GetControllerOf(rev)
	if owner == nil {
		log.Info("EdgeFunctionRevision is not controlled by an EdgeFunction, Skipping reconciliation.")
		return ctrl.Result{}, nil // Do not requeue for this version.
	}
	if owner.APIVersion != extensionsv1alpha2.GroupVersion.String() || owner.Kind != "EdgeFunction" {
		log.Info("EdgeFunctionRevision is not controlled by an EdgeFunction, Skipping reconciliation.", "owner", owner)
		return ctrl.Result{}, nil // Do not requeue for this version.
	}
	ef := &extensionsv1alpha2.EdgeFunction{}
	if err := r.Get(ctx, types.NamespacedName{Name: owner.Name}, ef); err != nil {
		log.Error(err, "Failed to get EdgeFunction owner")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !rev.DeletionTimestamp.IsZero() {
		if ef.Status.LiveRevision == rev.Name { // Do not delete the live revision.
			log.Info("EdgeFunctionRevision is the live revision, Skipping deletion.")
			return ctrl.Result{RequeueAfter: time.Second * 10}, nil
		}

		log.Info("Deleting EdgeFunctionRevision")

		if rev.Spec.Code.WasmSource != nil {
			log.Info("Deleting Wasm data", "ref", rev.Status.Ref)
			if err := r.wasmStore.Delete(ctx, rev.Status.Ref); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete Wasm data: %w", err)
			}
		} else if rev.Spec.Code.GoPluginSource != nil {
			log.Info("Deleting Go plugin data", "ref", rev.Status.Ref)
			if err := os.RemoveAll(filepath.Join(r.goStoreDir, rev.Status.Ref)); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete Go plugin data: %w", err)
			}
		} else if rev.Spec.Code.JsSource != nil {
			log.Info("Deleting Js data", "ref", rev.Status.Ref)
			if err := os.RemoveAll(filepath.Join(r.jsStoreDir, rev.Status.Ref)); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete Js data: %w", err)
			}

			if done, err := r.maybeCleanupEdgeRuntime(ctx, rev.Status.Ref); err != nil {
				log.Error(err, "Failed to cleanup Edge Runtime")
				return ctrl.Result{}, err
			} else if !done {
				log.Info("Edge Runtime is still running, waiting for termination")
				return ctrl.Result{RequeueAfter: time.Second * 10}, nil
			}
		}

		return ctrl.Result{}, nil
	}

	// Stage the EdgeFunctionRevision that was successfully ingested (has a Ready condition)
	// even if it's not Live yet.
	if !hasReadyCondition(rev.Status.Conditions) {
		log.Info("Revision is not Ready")
		return ctrl.Result{}, nil
	}

	ref := rev.Status.Ref
	log = log.WithValues("Ref", ref)

	if rev.Spec.Code.WasmSource != nil {
		log.Info("Wasm source detected")
		if r.wasmStore.Exists(ctx, ref) {
			log.Info("Wasm module already exists for ref")
			return ctrl.Result{}, nil
		}

		wasmData, err := r.downloadFuncData(clog.IntoContext(ctx, log), "wasm", ref)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to download Wasm data: %w", err)
		}

		if err := r.wasmStore.Set(ctx, ref, manifest.WithWasmData(wasmData)); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set Wasm data: %w", err)
		}

		log.Info("Stored Wasm data")
	} else if rev.Spec.Code.GoPluginSource != nil {
		log.Info("Go plugin source detected")

		if _, err := os.Stat(filepath.Join(r.goStoreDir, ref, "func.so")); err == nil {
			log.Info("Go plugin already exists for ref")
			return ctrl.Result{}, nil
		}

		soData, err := r.downloadFuncData(clog.IntoContext(ctx, log), "go", ref)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to download Wasm data: %w", err)
		}

		if err := os.MkdirAll(filepath.Join(r.goStoreDir, ref), 0755); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create Go plugin directory: %w", err)
		}

		if err := os.WriteFile(filepath.Join(r.goStoreDir, ref, "data"), soData, 0644); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to write Go plugin data: %w", err)
		}
		// Symlinking prevents Envoy from loading the plugin while it's being written to.
		if err := os.Symlink("data", filepath.Join(r.goStoreDir, ref, "func.so")); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create Go plugin symlink: %w", err)
		}
	} else if rev.Spec.Code.JsSource != nil {
		log.Info("Js source detected")

		if err := r.reconileEdgeRuntime(ctx, ref, rev.Spec.Runtime); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to reconile Edge Runtime: %w", err)
		}
	} else {
		log.Info("No source detected")
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func targetRefPredicate(proxyName string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}

		rev, ok := obj.(*extensionsv1alpha2.EdgeFunctionRevision)
		if !ok {
			return false
		}

		// TODO(dilyevsky): Check if the EdgeFunction is referenced by the HTTPRoute
		// attached to one of the managed Proxies.
		return true

		// Check if the EdgeFunction is owned by the Proxy.
		for _, owner := range rev.GetOwnerReferences() {
			if owner.APIVersion == corev1alpha2.GroupVersion.String() &&
				owner.Kind == "Proxy" &&
				owner.Name == proxyName {
				return true
			}
		}

		return false
	})
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *EdgeFunctionRevisionReconciler) SetupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
	proxyName string,
) error {
	if err := os.MkdirAll(filepath.Join(r.goStoreDir), 0755); err != nil {
		return fmt.Errorf("failed to create Go plugin directory: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1alpha2.EdgeFunctionRevision{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				targetRefPredicate(proxyName),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(r)
}
