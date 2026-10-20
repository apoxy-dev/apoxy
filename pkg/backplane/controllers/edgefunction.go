package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/backplane/wasm/manifest"
	"github.com/apoxy-dev/apoxy/pkg/edgefunc"
	edgefuncctrl "github.com/apoxy-dev/apoxy/pkg/edgefunc/controller"
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

	// edgeRuntime is the legacy per-function runtime (deprecated).
	edgeRuntime edgefunc.Runtime

	// edgeController is the new per-namespace controller.
	// When set, it takes precedence over edgeRuntime for JS functions.
	edgeController *edgefuncctrl.EdgeController

	// defaultNamespace is used when using the edgeController.
	defaultNamespace edgefuncctrl.Namespace

	// storeMu serializes every write and GC of the Go plugin store.
	storeMu sync.Mutex
	// mappedBlobs returns the blob names currently mmapped by any process.
	mappedBlobs func() (map[string]bool, error)
}

// EdgeFunctionRevisionReconcilerArgs contains the arguments for creating an EdgeFunctionRevisionReconciler.
type EdgeFunctionRevisionReconcilerArgs struct {
	Client        client.Client
	ReplicaName   string
	ApiserverHost string
	WasmStore     manifest.Store
	GoStoreDir    string
	JsStoreDir    string

	// EdgeRuntime is the legacy per-function runtime.
	// Either EdgeRuntime or EdgeController must be set.
	EdgeRuntime edgefunc.Runtime

	// EdgeController is the new per-namespace controller.
	// When set, it takes precedence over EdgeRuntime for JS functions.
	EdgeController   *edgefuncctrl.EdgeController
	DefaultNamespace edgefuncctrl.Namespace

	// MappedBlobs returns the Go plugin blob names currently mmapped by any
	// process. Defaults to scanning /proc/*/maps.
	MappedBlobs func() (map[string]bool, error)
}

// NewEdgeFunctionRevisionReconciler returns a new reconcile.Reconciler.
func NewEdgeFunctionRevisionReconciler(args EdgeFunctionRevisionReconcilerArgs) *EdgeFunctionRevisionReconciler {
	if args.MappedBlobs == nil {
		args.MappedBlobs = func() (map[string]bool, error) { return procMappedBlobs(args.GoStoreDir) }
	}
	return &EdgeFunctionRevisionReconciler{
		Client:           args.Client,
		replicaName:      args.ReplicaName,
		apiserverHost:    args.ApiserverHost,
		wasmStore:        args.WasmStore,
		goStoreDir:       args.GoStoreDir,
		jsStoreDir:       args.JsStoreDir,
		edgeRuntime:      args.EdgeRuntime,
		edgeController:   args.EdgeController,
		defaultNamespace: args.DefaultNamespace,
		mappedBlobs:      args.MappedBlobs,
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
	rev *extensionsv1alpha2.EdgeFunctionRevision,
	runtimeSpec *extensionsv1alpha2.EdgeFunctionRuntime,
) error {
	// Use new per-namespace controller if available.
	if r.edgeController != nil {
		return r.reconcileEdgeRuntimeWithController(ctx, rev)
	}

	// Fall back to legacy per-function runtime.
	return r.reconcileEdgeRuntimeLegacy(ctx, rev.Status.Ref, runtimeSpec)
}

// reconcileEdgeRuntimeWithController uses the new per-namespace EdgeController.
func (r *EdgeFunctionRevisionReconciler) reconcileEdgeRuntimeWithController(
	ctx context.Context,
	rev *extensionsv1alpha2.EdgeFunctionRevision,
) error {
	log := clog.FromContext(ctx)
	ref := rev.Status.Ref
	namespace := r.defaultNamespace

	log.Info("Reconciling Edge Runtime with controller", "namespace", namespace, "ref", ref)

	// Download eszip if not present.
	// For the controller mode, we write to the namespace's eszip directory.
	// The runtime manager will ensure the directory exists when the runtime starts.
	eszipPath := filepath.Join(r.jsStoreDir, string(namespace), ref+".eszip")
	if _, err := os.Stat(eszipPath); os.IsNotExist(err) {
		jsBundle, err := r.downloadFuncData(clog.IntoContext(ctx, log), "js", ref)
		if err != nil {
			return fmt.Errorf("failed to download Js data: %w", err)
		}

		if err := os.MkdirAll(filepath.Dir(eszipPath), 0755); err != nil {
			return fmt.Errorf("failed to create eszip directory: %w", err)
		}

		// Write the data file first, then create symlink for atomic update.
		dataPath := filepath.Join(r.jsStoreDir, string(namespace), ref+".data")
		if err := os.WriteFile(dataPath, jsBundle, 0644); err != nil {
			return fmt.Errorf("failed to write eszip data: %w", err)
		}
		if err := os.Symlink(ref+".data", eszipPath); err != nil {
			return fmt.Errorf("failed to create eszip symlink: %w", err)
		}

		log.Info("Downloaded and wrote eszip", "path", eszipPath, "size", len(jsBundle))
	} else if err != nil {
		return fmt.Errorf("failed to stat eszip: %w", err)
	}

	// Deploy using the EdgeController.
	if err := r.edgeController.Deploy(ctx, namespace, rev); err != nil {
		return fmt.Errorf("failed to deploy via EdgeController: %w", err)
	}

	log.Info("Deployed Edge Function via EdgeController", "ref", ref)

	return nil
}

// reconcileEdgeRuntimeLegacy uses the legacy per-function runtime.
func (r *EdgeFunctionRevisionReconciler) reconcileEdgeRuntimeLegacy(
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

	// Use new controller if available.
	if r.edgeController != nil {
		return r.maybeCleanupEdgeRuntimeWithController(ctx, ref)
	}

	// Fall back to legacy cleanup.
	return r.maybeCleanupEdgeRuntimeLegacy(ctx, ref)
}

// maybeCleanupEdgeRuntimeWithController cleans up using the new EdgeController.
func (r *EdgeFunctionRevisionReconciler) maybeCleanupEdgeRuntimeWithController(ctx context.Context, ref string) (bool, error) {
	log := clog.FromContext(ctx, "Ref", ref)
	namespace := r.defaultNamespace
	functionID := edgefuncctrl.FunctionID(ref)

	log.Info("Cleaning up Edge Runtime via EdgeController", "namespace", namespace, "functionID", functionID)

	if err := r.edgeController.Undeploy(ctx, namespace, functionID); err != nil {
		log.Error(err, "Failed to undeploy function")
		return false, err
	}

	// Also clean up the eszip file.
	eszipPath := filepath.Join(r.jsStoreDir, string(namespace), ref+".eszip")
	if err := os.Remove(eszipPath); err != nil && !os.IsNotExist(err) {
		log.Error(err, "Failed to delete eszip file")
	}
	dataPath := filepath.Join(r.jsStoreDir, string(namespace), ref+".data")
	if err := os.Remove(dataPath); err != nil && !os.IsNotExist(err) {
		log.Error(err, "Failed to delete data file")
	}

	log.Info("Edge Runtime cleaned up via EdgeController")

	return true, nil
}

// maybeCleanupEdgeRuntimeLegacy cleans up using the legacy per-function runtime.
func (r *EdgeFunctionRevisionReconciler) maybeCleanupEdgeRuntimeLegacy(ctx context.Context, ref string) (bool, error) {
	log := clog.FromContext(ctx, "Ref", ref)

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
		if apierrors.IsNotFound(err) {
			// Revisions are deleted without finalizers, so NotFound is the only delete signal.
			return ctrl.Result{}, r.cleanupDeletedGoRef(ctx, request.Name)
		}
		log.Error(err, "Failed to get EdgeFunctionRevision")
		return ctrl.Result{}, err
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
			if err := r.removeGoRef(ctx, rev.Status.Ref); err != nil {
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
			return ctrl.Result{}, fmt.Errorf("failed to download Go plugin data: %w", err)
		}

		blob, reused, err := r.storeGoPlugin(ref, soData)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to store Go plugin: %w", err)
		}
		log.Info("Stored Go plugin", "digest", blob, "reused", reused)
	} else if rev.Spec.Code.JsSource != nil {
		log.Info("Js source detected")

		if err := r.reconileEdgeRuntime(ctx, rev, rev.Spec.Runtime); err != nil {
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
	if err := os.MkdirAll(filepath.Join(r.goStoreDir, goBlobsDirName), 0755); err != nil {
		return fmt.Errorf("failed to create Go plugin directory: %w", err)
	}
	// Envoy is not started until the manager runs, so nothing is mapped yet.
	r.storeMu.Lock()
	r.gcBlobsLocked(ctx)
	r.storeMu.Unlock()

	if err := mgr.Add(&goStoreSweeper{r: r, cache: mgr.GetCache(), interval: goStoreSweepInterval}); err != nil {
		return fmt.Errorf("failed to add Go plugin store sweeper: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1alpha2.EdgeFunctionRevision{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				targetRefPredicate(proxyName),
			),
		).
		WithOptions(ctrlcontroller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(r)
}

// One inode per build: dlopen reuses a loaded (dev, ino), so identical bytes never start another Go runtime.
const (
	goBlobsDirName       = ".blobs"
	goBlobPrefix         = "sha256-"
	goBlobTmpPrefix      = ".tmp-"
	goFuncSoName         = "func.so"
	goFuncSoTmpName      = ".func.so.tmp"
	goStoreSweepInterval = 10 * time.Minute
)

// isSafeGoRef rejects refs that could escape goStoreDir or collide with .blobs.
func isSafeGoRef(ref string) bool {
	return ref != "" && ref == filepath.Base(ref) && !strings.HasPrefix(ref, ".")
}

// storeGoPlugin points go/<ref>/func.so at the content-addressed blob for data.
func (r *EdgeFunctionRevisionReconciler) storeGoPlugin(ref string, data []byte) (blob string, reused bool, err error) {
	if !isSafeGoRef(ref) {
		return "", false, fmt.Errorf("invalid Go plugin ref %q", ref)
	}

	r.storeMu.Lock()
	defer r.storeMu.Unlock()

	sum := sha256.Sum256(data)
	blob = goBlobPrefix + hex.EncodeToString(sum[:]) + ".so"
	blobsDir := filepath.Join(r.goStoreDir, goBlobsDirName)
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		return "", false, fmt.Errorf("failed to create Go plugin blob directory: %w", err)
	}
	if reused, err = writeBlob(blobsDir, blob, sum, data); err != nil {
		return "", false, err
	}

	refDir := filepath.Join(r.goStoreDir, ref)
	if err := os.MkdirAll(refDir, 0755); err != nil {
		return "", false, fmt.Errorf("failed to create Go plugin directory: %w", err)
	}
	tmpLink := filepath.Join(refDir, goFuncSoTmpName)
	if err := os.Remove(tmpLink); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", false, fmt.Errorf("failed to remove stale Go plugin symlink: %w", err)
	}
	if err := os.Symlink(filepath.Join("..", goBlobsDirName, blob), tmpLink); err != nil {
		return "", false, fmt.Errorf("failed to create Go plugin symlink: %w", err)
	}
	// Symlinking prevents Envoy from loading the plugin while it's being written to.
	if err := os.Rename(tmpLink, filepath.Join(refDir, goFuncSoName)); err != nil {
		return "", false, fmt.Errorf("failed to publish Go plugin symlink: %w", err)
	}
	return blob, reused, nil
}

// writeBlob never replaces an existing blob, so its inode (and loaded runtime) stays.
func writeBlob(blobsDir, blob string, sum [sha256.Size]byte, data []byte) (bool, error) {
	dst := filepath.Join(blobsDir, blob)
	if fi, err := os.Lstat(dst); err == nil {
		if !fi.Mode().IsRegular() {
			return false, fmt.Errorf("Go plugin blob %s is not a regular file", dst)
		}
		return true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("failed to stat Go plugin blob: %w", err)
	}

	f, err := os.CreateTemp(blobsDir, goBlobTmpPrefix+"*")
	if err != nil {
		return false, fmt.Errorf("failed to create Go plugin temp file: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return false, fmt.Errorf("failed to write Go plugin data: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return false, fmt.Errorf("failed to sync Go plugin data: %w", err)
	}
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return false, fmt.Errorf("failed to chmod Go plugin data: %w", err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("failed to close Go plugin data: %w", err)
	}
	written, err := os.ReadFile(tmp)
	if err != nil {
		return false, fmt.Errorf("failed to read back Go plugin data: %w", err)
	}
	if sha256.Sum256(written) != sum {
		return false, fmt.Errorf("Go plugin data digest mismatch after write")
	}
	return linkNoClobber(tmp, dst)
}

// linkNoClobber hard-links src to dst, keeping dst if it already exists.
func linkNoClobber(src, dst string) (existed bool, err error) {
	if err := os.Link(src, dst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return true, nil
		}
		return false, fmt.Errorf("failed to publish Go plugin blob: %w", err)
	}
	return false, nil
}

// removeGoRef removes go/<ref> and collects blobs it no longer references.
func (r *EdgeFunctionRevisionReconciler) removeGoRef(ctx context.Context, ref string) error {
	if !isSafeGoRef(ref) {
		clog.FromContext(ctx).Info("Refusing to remove Go plugin data for invalid ref", "ref", ref)
		return nil
	}
	r.storeMu.Lock()
	defer r.storeMu.Unlock()
	if err := os.RemoveAll(filepath.Join(r.goStoreDir, ref)); err != nil {
		return err
	}
	r.gcBlobsLocked(ctx)
	return nil
}

// cleanupDeletedGoRef removes go/<name>; Go plugin refs equal the revision name.
func (r *EdgeFunctionRevisionReconciler) cleanupDeletedGoRef(ctx context.Context, name string) error {
	log := clog.FromContext(ctx)
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 || !isSafeGoRef(name) {
		log.Info("Refusing Go plugin cleanup for invalid revision name", "name", name, "errors", errs)
		return nil
	}
	if _, err := os.Lstat(filepath.Join(r.goStoreDir, name)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	log.Info("EdgeFunctionRevision deleted, removing Go plugin data", "ref", name)
	if err := r.removeGoRef(ctx, name); err != nil {
		return fmt.Errorf("failed to delete Go plugin data: %w", err)
	}
	return nil
}

// gcBlobsLocked runs gcBlobs and logs the outcome. Caller holds storeMu.
func (r *EdgeFunctionRevisionReconciler) gcBlobsLocked(ctx context.Context) {
	log := clog.FromContext(ctx)
	removed, err := gcBlobs(r.goStoreDir, r.mappedBlobs)
	if err != nil {
		log.Error(err, "Go plugin blob GC skipped")
		return
	}
	if len(removed) > 0 {
		log.Info("Removed unused Go plugin blobs", "blobs", removed)
	}
}

// gcBlobs keeps mapped blobs: deleting one frees nothing and gives the next identical build a second runtime.
func gcBlobs(goStoreDir string, mapped func() (map[string]bool, error)) ([]string, error) {
	blobsDir := filepath.Join(goStoreDir, goBlobsDirName)
	entries, err := os.ReadDir(blobsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to list Go plugin blobs: %w", err)
	}
	inUse, err := mapped()
	if err != nil {
		return nil, fmt.Errorf("failed to list mapped Go plugin blobs: %w", err)
	}
	refd, err := referencedBlobs(goStoreDir)
	if err != nil {
		return nil, err
	}

	var removed []string
	for _, e := range entries {
		name := e.Name()
		isTmp := strings.HasPrefix(name, goBlobTmpPrefix)
		isUnused := strings.HasPrefix(name, goBlobPrefix) && !refd[name] && !inUse[name]
		if !isTmp && !isUnused {
			continue
		}
		if err := os.Remove(filepath.Join(blobsDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, fmt.Errorf("failed to remove Go plugin blob %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// readlink is a seam so tests can fail reference reads as root.
var readlink = os.Readlink

// referencedBlobs returns the blob names that some go/<ref>/func.so points at.
func referencedBlobs(goStoreDir string) (map[string]bool, error) {
	entries, err := os.ReadDir(goStoreDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list Go plugin refs: %w", err)
	}
	blobsDir := filepath.Clean(filepath.Join(goStoreDir, goBlobsDirName))
	refd := make(map[string]bool)
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		refDir := filepath.Join(goStoreDir, e.Name())
		target, err := readlink(filepath.Join(refDir, goFuncSoName))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.EINVAL) {
			continue
		} else if err != nil {
			// An unreadable reference could be live, so GC must not proceed.
			return nil, fmt.Errorf("failed to read Go plugin ref %s: %w", e.Name(), err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(refDir, target)
		}
		if filepath.Dir(filepath.Clean(target)) == blobsDir {
			refd[filepath.Base(target)] = true
		}
	}
	return refd, nil
}

// procMappedBlobs scans /proc/*/maps for files under the canonical blob dir.
func procMappedBlobs(goStoreDir string) (map[string]bool, error) {
	root, err := filepath.EvalSymlinks(goStoreDir)
	if err != nil {
		return nil, err
	}
	prefix := filepath.Join(root, goBlobsDirName) + string(filepath.Separator)
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	self := strconv.Itoa(os.Getpid())
	sawSelf := false
	mapped := make(map[string]bool)
	for _, p := range procs {
		if !p.IsDir() || !isAllDigits(p.Name()) {
			continue
		}
		maps, err := os.ReadFile(filepath.Join("/proc", p.Name(), "maps"))
		if err != nil {
			// The process exited between ReadDir and ReadFile.
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			return nil, err
		}
		if p.Name() == self {
			sawSelf = true
		}
		for _, line := range strings.Split(string(maps), "\n") {
			i := strings.Index(line, prefix)
			if i < 0 {
				continue
			}
			mapped[strings.TrimSuffix(line[i+len(prefix):], " (deleted)")] = true
		}
	}
	// Guards against /proc being an empty dir rather than procfs.
	if !sawSelf {
		return nil, fmt.Errorf("own process not found in /proc")
	}
	return mapped, nil
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// sweepOrphans catches revisions deleted while the backplane was down.
func (r *EdgeFunctionRevisionReconciler) sweepOrphans(ctx context.Context) error {
	r.storeMu.Lock()
	defer r.storeMu.Unlock()

	var revs extensionsv1alpha2.EdgeFunctionRevisionList
	if err := r.List(ctx, &revs); err != nil {
		return fmt.Errorf("failed to list EdgeFunctionRevisions: %w", err)
	}
	live := make(map[string]bool, 2*len(revs.Items))
	for _, rev := range revs.Items {
		live[rev.Name] = true
		if rev.Status.Ref != "" {
			live[rev.Status.Ref] = true
		}
	}

	entries, err := os.ReadDir(r.goStoreDir)
	if err != nil {
		return fmt.Errorf("failed to list Go plugin refs: %w", err)
	}
	log := clog.FromContext(ctx)
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || live[e.Name()] {
			continue
		}
		log.Info("Removing orphaned Go plugin data", "ref", e.Name())
		if err := os.RemoveAll(filepath.Join(r.goStoreDir, e.Name())); err != nil {
			return fmt.Errorf("failed to remove orphaned Go plugin data: %w", err)
		}
	}
	r.gcBlobsLocked(ctx)
	return nil
}

// goStoreSweeper runs sweepOrphans after the cache syncs and then periodically.
type goStoreSweeper struct {
	r        *EdgeFunctionRevisionReconciler
	cache    cache.Cache
	interval time.Duration
}

// NeedLeaderElection is false: every replica owns its own local store.
func (s *goStoreSweeper) NeedLeaderElection() bool { return false }

// Start never returns an error, since that would stop the manager.
func (s *goStoreSweeper) Start(ctx context.Context) error {
	log := clog.FromContext(ctx).WithName("go-store-sweeper")
	ctx = clog.IntoContext(ctx, log)
	if !s.cache.WaitForCacheSync(ctx) {
		return nil
	}
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		if err := s.r.sweepOrphans(ctx); err != nil {
			log.Error(err, "Go plugin store sweep failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
