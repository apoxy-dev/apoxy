package ingest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.temporal.io/sdk/activity"
	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/temporal"
	tworker "go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	k8scorev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubernetes/pkg/credentialprovider"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	orasretry "oras.land/oras-go/v2/registry/remote/retry"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	EdgeFunctionIngestQueue = "EDGE_FUNC_INGEST_TASK_QUEUE"
)

const (
	InvalidInputError = "InvalidInputError"
)

type EdgeFunctionIngestParams struct {
	Obj *extensionsv1alpha2.EdgeFunctionRevision
}

type IngestResult struct {
	AssetFilePath      string
	AssetFileCreatedAt metav1.Time
	Err                string
}

// RegisterWorkflows registers Edge Function workflows with the Temporal worker.
func RegisterWorkflows(w tworker.Worker) {
	w.RegisterWorkflow(EdgeFunctionIngestWorkflow)
	w.RegisterWorkflow(EdgeFunctionCleanupWorkflow)
}

// EdgeFunctionIngestWorkflow is a Temporal workflow that ingests Edge Functions.
// The function code is
func EdgeFunctionIngestWorkflow(ctx workflow.Context, in *EdgeFunctionIngestParams) error {
	opts := workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute, // 10 min to download WASM file should be enough?
		// HeartbeatTimeout:    2 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:        time.Second,
			BackoffCoefficient:     5.0,
			MaximumInterval:        60 * time.Second,
			MaximumAttempts:        5,
			NonRetryableErrorTypes: []string{"FatalError"},
		},
	}
	ctx = workflow.WithActivityOptions(ctx, opts)
	log := tlog.With(workflow.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	so := &workflow.SessionOptions{
		CreationTimeout:  time.Minute,
		ExecutionTimeout: 5 * time.Minute,
	}
	sessCtx, err := workflow.CreateSession(ctx, so)
	if err != nil {
		return err
	}
	defer workflow.CompleteSession(sessCtx)

	var w *worker
	var res IngestResult

	if err := workflow.ExecuteActivity(ctx, w.AddIngestConditionActivity, in).Get(ctx, nil); err != nil {
		return err
	}

	// Reflect if more than one pointer set.
	cv := reflect.ValueOf(in.Obj.Spec.Code)
	var fSet []reflect.Value
	for _, f := range reflect.VisibleFields(cv.Type()) {
		if f.Anonymous { // Skip embedded fields.
			continue
		}
		fv := cv.FieldByIndex(f.Index)
		if fv.Kind() == reflect.Ptr && !fv.IsNil() {
			fSet = append(fSet, fv)
		}
	}
	switch len(fSet) {
	case 0:
		err = errors.New("Edge Function must have either WASM or JS source")
	case 1:
		switch fSet[0].Interface().(type) {
		case *extensionsv1alpha2.WasmSource:
			log.Info("EdgeFunctionRevision ingest started", "Source", "WASM")
			err = workflow.ExecuteActivity(sessCtx, w.DownloadWasmActivity, in).Get(sessCtx, &res)
			if err != nil {
				log.Error("Download activity failed", "Error", err)
				goto Finalize
			}

			log.Info("EdgeFunctionRevision .wasm staged successfully", "WasmFilePath", res.AssetFilePath)

			err = workflow.ExecuteActivity(sessCtx, w.StoreWasmActivity, in, res).Get(sessCtx, nil)
			if err != nil {
				log.Error("Store activity failed", "Error", err)
				goto Finalize
			}
		case *extensionsv1alpha2.JavaScriptSource:
			log.Info("EdgeFunctionRevision ingest started", "Source", "JS")
			if err = workflow.ExecuteActivity(sessCtx, w.DownloadJsActivity, in).Get(sessCtx, &res); err != nil {
				log.Error("Failed to download JS source", "Error", err)
				goto Finalize
			}

			log.Info("EdgeFunctionRevision .eszip staged successfully", "EsZipPath", res.AssetFilePath)

			if err = workflow.ExecuteActivity(sessCtx, w.BundleJsActivity, in, res).Get(sessCtx, &res); err != nil {
				log.Error("Failed to bundle JS source", "Error", err)
				goto Finalize
			}

			if err = workflow.ExecuteActivity(sessCtx, w.StoreEsZipActivity, in, res).Get(sessCtx, nil); err != nil {
				log.Error("Store activity failed", "Error", err)
				goto Finalize
			}
		case *extensionsv1alpha2.GoPluginSource:
			log.Info("EdgeFunctionRevision ingest started", "Source", "GoPlugin")
			err = workflow.ExecuteActivity(sessCtx, w.DownloadGoPluginActivity, in).Get(sessCtx, &res)
			if err != nil {
				log.Error("Download activity failed", "Error", err)
				goto Finalize
			}

			log.Info("EdgeFunctionRevision Go plugin staged successfully", "GoPluginFilePath", res.AssetFilePath)
			err = workflow.ExecuteActivity(sessCtx, w.StoreGoPluginActivity, in, res).Get(sessCtx, nil)
			if err != nil {
				log.Error("Store activity failed", "Error", err)
				goto Finalize
			}
		default:
			err = fmt.Errorf("Edge Function has invalid source type: %v", reflect.TypeOf(fSet[0].Interface()))
		}
	default:
		var names []string
		for _, f := range fSet {
			names = append(names, f.Type().Name())
		}
		err = fmt.Errorf("EdgeFunctionRevision must have either WASM or JS source, got %s", strings.Join(names, ", "))
	}

Finalize:
	var appErr *temporal.ApplicationError
	if errors.As(err, &appErr) {
		res.Err = appErr.Error()
	}
	cleanErr := workflow.ExecuteActivity(sessCtx, w.CleanupStagedData, in).Get(ctx, nil)
	if cleanErr != nil {
		log.Error("Failed to cleanup staged data", "Error", cleanErr)
	}
	finErr := workflow.ExecuteActivity(sessCtx, w.FinalizeActivity, in, &res).Get(ctx, nil)
	if finErr != nil {
		log.Error("Failed to finalize Edge Function ingest", "Error", finErr)
		return finErr
	}

	log.Info("Edge Function ingest completed successfully")
	return nil
}

func EdgeFunctionCleanupWorkflow(ctx workflow.Context, in *EdgeFunctionIngestParams) error {
	opts := workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    10 * time.Second,
			MaximumAttempts:    3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, opts)
	log := tlog.With(workflow.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	var w *worker

	if err := workflow.ExecuteActivity(ctx, w.CleanupStagedData, in).Get(ctx, nil); err != nil {
		log.Error("Failed to cleanup staged data", "Error", err)
		return err
	}

	if err := workflow.ExecuteActivity(ctx, w.CleanupStoredData, in).Get(ctx, nil); err != nil {
		log.Error("Failed to cleanup stored data", "Error", err)
		return err
	}

	log.Info("Edge Function cleanup completed successfully")
	return nil
}

// Worker implements Temporal Activities for Edge Functions Ingest queue.
type worker struct {
	k8s     kubernetes.Interface
	a3y     versioned.Interface
	baseDir string
}

// NewWorker returns a new worker for Edge Functions Ingest queue.
func NewWorker(kc *rest.Config, c versioned.Interface, baseDir string) *worker {
	w := &worker{
		a3y:     c,
		baseDir: baseDir,
	}
	if kc != nil {
		w.k8s = kubernetes.NewForConfigOrDie(kc)
	}
	return w
}

// RegisterActivities registers Edge Functions Ingest activities with
// the Temporal worker instance.
func (w *worker) RegisterActivities(tw tworker.Worker) {
	tw.RegisterActivity(w.AddIngestConditionActivity)
	tw.RegisterActivity(w.DownloadWasmActivity)
	tw.RegisterActivity(w.StoreWasmActivity)
	tw.RegisterActivity(w.DownloadJsActivity)
	tw.RegisterActivity(w.BundleJsActivity)
	tw.RegisterActivity(w.StoreEsZipActivity)
	tw.RegisterActivity(w.DownloadGoPluginActivity)
	tw.RegisterActivity(w.StoreGoPluginActivity)
	tw.RegisterActivity(w.FinalizeActivity)
	tw.RegisterActivity(w.CleanupStagedData)
	tw.RegisterActivity(w.CleanupStoredData)
}

func (w *worker) AddIngestConditionActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Adding ingest condition to EdgeFunctionRevision")

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		rev, err := w.a3y.ExtensionsV1alpha2().EdgeFunctionRevisions().Get(ctx, in.Obj.Name, metav1.GetOptions{})
		if err != nil {
			log.Error("Failed to get EdgeFunctionRevision", "Error", err)
			return err
		}

		rev.Status.Conditions = append(rev.Status.Conditions, metav1.Condition{
			Type:               "Ingest",
			Status:             metav1.ConditionTrue,
			Reason:             "InProgress",
			Message:            "Edge Function code is being ingested",
			LastTransitionTime: metav1.NewTime(time.Now()),
		})

		if _, err := w.a3y.ExtensionsV1alpha2().EdgeFunctionRevisions().UpdateStatus(ctx, rev, metav1.UpdateOptions{}); err != nil {
			log.Error("Failed to update Edge Function status", "Error", err)
			return err
		}

		log.Info("Edge Function ingest condition added successfully")
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (w *worker) stagingDir(name, rid string) string {
	return filepath.Join(w.baseDir, "run", "ingest", "staging", name, rid)
}

func (w *worker) storeDir(name string) string {
	return filepath.Join(w.baseDir, "/run", "ingest", "store", name)
}

const (
	// MaxFileSize is the maximum size of the file that can be downloaded.
	MaxFileSize = 50 * 1024 * 1024 // 50MB
	// MaxErrorSize is the maximum size of the error message that can be returned.
	MaxErrorSize = 1024
)

func (w *worker) downloadFile(ctx context.Context, url, target string) (os.FileInfo, error) {
	c := http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Check if body contains error message
		// If so, return that error message
		var msg []byte
		if resp.ContentLength > MaxErrorSize {
			msg = []byte("Error message too large to display")
		} else {
			var err error
			msg, err = io.ReadAll(io.LimitReader(resp.Body, MaxErrorSize))
			if err != nil {
				msg = []byte("Failed to read error message")
			}
		}

		return nil, fmt.Errorf("Failed to download file: %s (%s)", resp.Status, string(msg))
	}

	if resp.ContentLength > MaxFileSize {
		return nil, fmt.Errorf("File size exceeds maximum allowed size: %d", resp.ContentLength)
	}

	tf, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(tf, io.LimitReader(resp.Body, MaxFileSize)); err != nil {
		return nil, err
	}

	return tf.Stat()
}

// DownloadWasmActivity downloads the Edge Function .wasm file.
func (w *worker) DownloadWasmActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) (*IngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	d := w.stagingDir(in.Obj.Name, rid)

	if err := os.MkdirAll(d, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return nil, err
	}

	wasmFile := filepath.Join(d, "func.wasm")
	stat, err := w.downloadFile(ctx, in.Obj.Spec.Code.WasmSource.URL, wasmFile)
	if err != nil {
		log.Error("Failed to download WASM file", "Error", err)
		return nil, err
	}

	return &IngestResult{
		AssetFilePath:      wasmFile,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

// StoreWasmActivity stores the Edge Function .wasm file in the object store.
func (w *worker) StoreWasmActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	res *IngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Storing Edge Function .wasm file in object store")

	targetDir := w.storeDir(in.Obj.Name)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return err
	}

	targetFile := filepath.Join(targetDir, "func.wasm")
	// TODO(dilyevsky): Use object store API to store the file.
	// For now, just link the file to the target directory.
	if err := os.Rename(res.AssetFilePath, targetFile); err != nil {
		log.Error("Failed to link WASM file", "Error", err)
		return err
	}

	return nil
}

func (w *worker) pullOCIImage(
	ctx context.Context,
	log tlog.Logger,
	targetPath string,
	ociRef *extensionsv1alpha2.OCIImageRef,
) (os.FileInfo, error) {
	log.Info("Pulling OCI image", "Ref", ociRef)

	fs, err := file.New(filepath.Dir(targetPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create file system: %w", err)
	}
	defer fs.Close()

	repo, err := remote.NewRepository(ociRef.Repo)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	var credsFunc auth.CredentialFunc
	if ociRef.Credentials != nil {
		pwd := make([]byte, base64.StdEncoding.DecodedLen(len(ociRef.Credentials.PasswordData)))
		n, err := base64.StdEncoding.Decode(pwd, ociRef.Credentials.PasswordData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode password: %w", err)
		}
		pwd = pwd[:n]

		credsFunc = auth.StaticCredential(
			repo.Reference.Registry,
			auth.Credential{
				Username: ociRef.Credentials.Username,
				Password: string(pwd),
			},
		)
	} else if secretRef := ociRef.CredentialsRef; secretRef != nil {
		if secretRef.Group == "" && secretRef.Kind == "Secret" {
			// Secret refs are only valid in k8s environment.
			if w.k8s == nil {
				return nil, errors.New("k8s environment is not set")
			}

			log.Info("Getting OCI credentials from secret", "SecretNamespace", secretRef.Namespace, "SecretName", secretRef.Name)

			secret, err := w.k8s.CoreV1().Secrets(string(secretRef.Namespace)).Get(ctx, string(secretRef.Name), metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to get secret: %w", err)
			}
			if secret.Type != k8scorev1.SecretTypeDockerConfigJson {
				return nil, fmt.Errorf("invalid secret type %q, expected %q", secret.Type, "kubernetes.io/dockerconfigjson")
			}
			confJson := secret.Data[".dockerconfigjson"]
			if len(confJson) == 0 {
				return nil, fmt.Errorf("no .dockerconfigjson data found in secret")
			}
			var dockerConfig credentialprovider.DockerConfigJSON
			if err := json.Unmarshal(confJson, &dockerConfig); err != nil {
				return nil, fmt.Errorf("failed to parse dockerconfigjson: %w", err)
			}
			keyring := &credentialprovider.BasicDockerKeyring{}
			keyring.Add(nil, dockerConfig.Auths)

			credsFunc = func(_ context.Context, _ string) (auth.Credential, error) {
				authConfs, ok := keyring.Lookup(ociRef.Repo)
				if !ok {
					return auth.EmptyCredential, fmt.Errorf("no credentials found for repository %s", ociRef.Repo)
				}
				if len(authConfs) == 0 {
					return auth.EmptyCredential, fmt.Errorf("no credentials found for repository %s", ociRef.Repo)
				}
				authConf := authConfs[0]
				log.Info("Found credentials for registry", "repository", ociRef.Repo, "username", authConf.Username)
				return auth.Credential{
					Username: authConf.Username,
					Password: authConf.Password,
				}, nil
			}
		} else {
			// TODO(dilyevsky): Support other kinds of secrets for non-k8s environments.
			return nil, fmt.Errorf("invalid secret kind %q, expected %q", secretRef.Kind, "Secret")
		}
	} else {
		log.Debug("No credentials provided for OCI registry")
	}

	repo.Client = &auth.Client{
		Client:     orasretry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: credsFunc,
	}

	opts := oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{
			PreCopy: func(ctx context.Context, desc ocispecv1.Descriptor) error {
				log.Debug("Pre-copy", "MediaType", desc.MediaType)
				if desc.MediaType == ocispecv1.MediaTypeImageManifest ||
					desc.MediaType == extensionsv1alpha2.ImageLayerMediaType {
					return nil
				}
				return oras.SkipNode
			},
		},
	}
	opts.WithTargetPlatform(&ocispecv1.Platform{
		Architecture: runtime.GOARCH,
		OS:           "linux",
	})
	manifest, err := oras.Copy(ctx, repo, ociRef.Tag, fs, "", opts)
	if err != nil {
		return nil, fmt.Errorf("failed to pull OCI image: %w", err)
	}

	log.Info("OCI image pulled", "Digest", manifest.Digest.String())

	if manifest.MediaType != ocispecv1.MediaTypeImageManifest {
		return nil, fmt.Errorf("unexpected manifest media type: %s", manifest.MediaType)
	}

	manifestblob, err := content.FetchAll(ctx, fs, manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest blob: %w", err)
	}
	var imgManifest ocispecv1.Manifest
	if err := json.Unmarshal(manifestblob, &imgManifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if len(imgManifest.Layers) == 0 {
		return nil, fmt.Errorf("no layers found in the manifest")
	}

	// See: https://oras.land/docs/concepts/artifact#determining-the-artifact-type
	if imgManifest.ArtifactType != extensionsv1alpha2.ImageConfigMediaType ||
		imgManifest.Config.MediaType != extensionsv1alpha2.ImageConfigMediaType {
		for _, layer := range imgManifest.Layers {
			if layer.MediaType == extensionsv1alpha2.ImageLayerMediaType {
				log.Info("Found image layer", "Digest", layer.Digest.String())
				tar, err := content.FetchAll(ctx, fs, layer)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch layer: %w", err)
				}

				if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
					return nil, fmt.Errorf("failed to create target directory: %w", err)
				}
				if err := os.WriteFile(targetPath, tar, 0644); err != nil {
					return nil, fmt.Errorf("failed to write file: %w", err)
				}

				return os.Stat(targetPath)
			}
		}
	}

	return nil, fmt.Errorf("no image layer found in the manifest")
}

// DownloadGoPluginActivity downloads the Edge Function Go plugin .so file and stores it in the staging directory.
func (w *worker) DownloadGoPluginActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) (*IngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	log.Info("Downloading Edge Function Go plugin .so file", "URL", in.Obj.Spec.Code.GoPluginSource.URL)

	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	targetDir := w.stagingDir(in.Obj.Name, rid)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return nil, err
	}

	if in.Obj.Spec.Code.GoPluginSource.OCI != nil && in.Obj.Spec.Code.GoPluginSource.URL != nil {
		return nil, fmt.Errorf("both OCI and URL sources are specified")
	}

	soFile := filepath.Join(targetDir, "func.so")
	var stat os.FileInfo
	var err error
	if in.Obj.Spec.Code.GoPluginSource.OCI != nil {
		stat, err = w.pullOCIImage(ctx, log, soFile, in.Obj.Spec.Code.GoPluginSource.OCI)
		if err != nil {
			log.Error("Failed to pull OCI image", "Error", err)
			return nil, err
		}
	} else if in.Obj.Spec.Code.GoPluginSource.URL != nil {
		stat, err = w.downloadFile(ctx, *in.Obj.Spec.Code.GoPluginSource.URL, soFile)
		if err != nil {
			log.Error("Failed to download .so file", "Error", err)
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("no source specified")
	}

	return &IngestResult{
		AssetFilePath:      soFile,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

// StoreGoPluginActivity stores the Edge Function Go plugin .so file in the object store.
func (w *worker) StoreGoPluginActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	out *IngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Storing Edge Function .so file in object store")

	targetDir := w.storeDir(in.Obj.Name)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return err
	}

	targetFile := filepath.Join(targetDir, "func.so")
	// TODO(dilyevsky): Use object store API to store the file.
	// For now, just link the file to the target directory.
	if err := os.Rename(out.AssetFilePath, targetFile); err != nil {
		log.Error("Failed to link WASM file", "Error", err)
		return err
	}

	return nil
}

func (w *worker) DownloadJsActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) (*IngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	jsDir := filepath.Join(w.stagingDir(in.Obj.Name, rid), "js")
	if err := os.MkdirAll(jsDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return nil, err
	}
	stat, err := os.Stat(jsDir)
	if err != nil {
		log.Error("Failed to stat target directory", "Error", err)
		return nil, err
	}

	if in.Obj.Spec.Code.JsSource.Assets != nil {
		for _, f := range in.Obj.Spec.Code.JsSource.Assets.Files {
			targetFile := filepath.Join(jsDir, filepath.Clean(f.Path))
			if err := os.MkdirAll(filepath.Dir(targetFile), 0755); err != nil {
				log.Error("Failed to create target directory for asset", "Error", err)
				return nil, err
			}
			dstFile, err := os.Create(targetFile)
			if err != nil {
				log.Error("Failed to create js file", "Error", err)
				return nil, err
			}
			defer dstFile.Close()

			r := strings.NewReader(f.Content)
			if _, err := io.Copy(dstFile, r); err != nil {
				log.Error("Failed to copy file content", "Error", err)
				return nil, err
			}
		}
	} else if in.Obj.Spec.Code.JsSource.Git != nil {
		return nil, fmt.Errorf("Git source not supported yet")
	} else {
		return nil, fmt.Errorf("No source specified")
	}
	if err != nil {
		log.Error("Failed to download JS file", "Error", err)
		return nil, err
	}

	return &IngestResult{
		AssetFilePath:      jsDir,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

func (w *worker) BundleJsActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	res *IngestResult,
) (*IngestResult, error) {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	d := w.stagingDir(in.Obj.Name, rid)
	binDir := filepath.Join(d, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		log.Error("Failed to create bin directory", "Error", err)
		return nil, err
	}
	esZip := filepath.Join(binDir, "bin.eszip")

	log.Info("Bundling JS files", "Directory", d)

	entry := filepath.Join(res.AssetFilePath, in.Obj.Spec.Code.JsSource.Entrypoint)
	log.Debug("Checking entrypoint exists", "Entry", entry)
	if _, err := os.Stat(entry); err != nil {
		log.Error("Entrypoint not found", "Error", err)
		return nil, err
	}
	cmd := exec.CommandContext(
		ctx,
		"edge-runtime", "bundle",
		"--entrypoint", entry,
		"--output", esZip,
	)

	log.Info("Running edge-runtime bundle", "Command", cmd.String())

	if out, err := cmd.CombinedOutput(); err != nil {
		log.Error("Failed to bundle JS files", "Error", err, "Output", string(out))
		return nil, temporal.NewNonRetryableApplicationError("Failed to bundle JS files", "", err)
	}

	stat, err := os.Stat(esZip)
	if err != nil {
		log.Error("Failed to find bundled eszip", "Error", err)
		return nil, err
	}

	return &IngestResult{
		AssetFilePath:      esZip,
		AssetFileCreatedAt: metav1.NewTime(stat.ModTime()),
	}, nil
}

func (w *worker) StoreEsZipActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	res *IngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)

	storeDir := w.storeDir(in.Obj.Name)
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		log.Error("Failed to create target directory", "Error", err)
		return err
	}

	log.Info("Storing JS bundle", "Directory", storeDir)

	targetFile := filepath.Join(storeDir, "bin.eszip")
	// TODO(dilyevsky): Use object store API to store the file.
	// For now, just link the file to the target directory.
	if err := os.Rename(res.AssetFilePath, targetFile); err != nil {
		log.Error("Failed to link WASM file", "Error", err)
		return err
	}

	return nil
}

// This activity is responsible for updating the Edge Function status.
func (w *worker) FinalizeActivity(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
	res *IngestResult,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Finalizing Edge Function ingest", "Error", res.Err)

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		log.Info("Updating EdgeFunctionRevision status")

		rev, err := w.a3y.ExtensionsV1alpha2().EdgeFunctionRevisions().Get(ctx, in.Obj.Name, metav1.GetOptions{})
		if err != nil {
			log.Error("Failed to get EdgeFunctionRevision", "Error", err)
			return err
		}

		if res.Err != "" {
			rev.Status.Conditions = append(rev.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				Reason:             "Failed",
				Message:            res.Err,
				LastTransitionTime: metav1.NewTime(time.Now()),
			})
		} else {
			rev.Status.Conditions = append(rev.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Ready",
				Message:            "Ready",
				LastTransitionTime: metav1.NewTime(time.Now()),
			})

			rev.Status.Ref = in.Obj.Name
		}

		if _, err := w.a3y.ExtensionsV1alpha2().EdgeFunctionRevisions().UpdateStatus(ctx, rev, metav1.UpdateOptions{}); err != nil {
			log.Error("Failed to update Edge Function status", "Error", err)
			return err
		}

		log.Info("Edge Function status updated successfully")

		return nil
	}); err != nil {
		return err
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		log.Info("Updating EdgeFunction status")

		var fun *extensionsv1alpha2.EdgeFunction
		for _, ref := range in.Obj.OwnerReferences {
			if ref.Kind != "EdgeFunction" {
				continue
			}
			var err error
			fun, err = w.a3y.ExtensionsV1alpha2().EdgeFunctions().Get(ctx, ref.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get owner EdgeFunction: %w", err)
			}
			break
		}
		if fun == nil {
			log.Error("No owner EdgeFunction found")
			return fmt.Errorf("no owner EdgeFunction found")
		}

		if res.Err != "" {
			// If there is no live revision to use, the function is not ready.
			if fun.Status.LiveRevision == "" {
				if !hasCondition(fun.Status.Conditions, "Ready", metav1.ConditionFalse) {
					fun.Status.Conditions = append(fun.Status.Conditions, metav1.Condition{
						Type:               "Ready",
						Status:             metav1.ConditionFalse,
						Reason:             "Failed",
						Message:            res.Err,
						LastTransitionTime: metav1.NewTime(time.Now()),
					})
				}
			}
		} else {
			if !hasCondition(fun.Status.Conditions, "Ready", metav1.ConditionTrue) {
				fun.Status.Conditions = append(fun.Status.Conditions, metav1.Condition{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Ready",
					Message:            "Ready",
					LastTransitionTime: metav1.NewTime(time.Now()),
				})
			}
		}

		fun.Status.LiveRevision = in.Obj.Name

		return nil
	})
}

func (w *worker) CleanupStagedData(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Cleaning up staged data")

	rid := activity.GetInfo(ctx).WorkflowExecution.RunID
	stagingDir := filepath.Dir(w.stagingDir(in.Obj.Name, rid))

	log.Info("Removing staging directory", "Directory", stagingDir)

	if err := os.RemoveAll(stagingDir); err != nil {
		log.Error("Failed to remove staging directory", "Error", err)
		return err
	}

	log.Info("Staging directory cleaned up successfully")
	return nil
}

func (w *worker) CleanupStoredData(
	ctx context.Context,
	in *EdgeFunctionIngestParams,
) error {
	log := tlog.With(activity.GetLogger(ctx), "Name", in.Obj.Name, "ResourceVersion", in.Obj.ResourceVersion)
	log.Info("Cleaning up stored data")

	storeDir := w.storeDir(in.Obj.Name)
	if err := os.RemoveAll(storeDir); err != nil {
		log.Error("Failed to remove store directory", "Error", err)
		return err
	}

	log.Info("Store directory cleaned up successfully")
	return nil
}

func hasCondition(conditions []metav1.Condition, condType string, status metav1.ConditionStatus) bool {
	for _, c := range conditions {
		if c.Type == condType && c.Status == status {
			return true
		}
	}
	return false
}

// ListenAndServeEdgeFuncs starts an HTTP server to serve the Edge Function .wasm file.
func (w *worker) ListenAndServeEdgeFuncs(host string, port int) error {
	mux := http.NewServeMux()
	mux.Handle("/wasm/", w)
	mux.Handle("/go/", w)
	mux.Handle("/js/", w)
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Infof("Listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (w *worker) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	log.Infof("Serving %s", req.URL.Path)
	path := filepath.Clean(strings.TrimLeft(req.URL.Path, "/"))
	ss := strings.Split(path, "/")
	if len(ss) != 2 {
		log.Errorf("Invalid path %s", path)
		http.Error(wr, "Invalid path", http.StatusBadRequest)
		return
	}
	t, name := ss[0], ss[1]
	if name == "" {
		log.Errorf("Name is required: %s", path)
		http.Error(wr, "Name is required", http.StatusBadRequest)
		return
	}
	var p string
	switch t {
	case "wasm":
		p = w.storeDir(name) + "/func.wasm"
	case "go":
		p = w.storeDir(name) + "/func.so"
	case "js":
		p = w.storeDir(name) + "/bin.eszip"
	default:
		log.Errorf("Invalid type %s", t)
		http.Error(wr, "Invalid type", http.StatusBadRequest)
		return
	}

	log.Infof("Serving edge function %s from %s", name, p)

	if _, err := os.Stat(p); err != nil {
		log.Errorf("Failed to stat %s", p)
		http.Error(wr, "File not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		log.Errorf("Failed to open %s for reading", p)
		http.Error(wr, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	wr.Header().Set("Content-Type", "application/octet-stream")

	if _, err := io.Copy(wr, f); err != nil {
		http.Error(wr, "Failed to copy file", http.StatusInternalServerError)
		return
	}

	wr.WriteHeader(http.StatusOK)
}
