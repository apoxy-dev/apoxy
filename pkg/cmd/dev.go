package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/util/retry"

	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/apiserver"
	"github.com/apoxy-dev/apoxy/pkg/backplane/portforward"
	chdrivers "github.com/apoxy-dev/apoxy/pkg/clickhouse/drivers"
	"github.com/apoxy-dev/apoxy/pkg/clickhouse/migrations"
	"github.com/apoxy-dev/apoxy/pkg/drivers"
	"github.com/apoxy-dev/apoxy/pkg/log"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

var (
	rs             = runtime.NewScheme()
	codecFactory   = serializer.NewCodecFactory(rs)
	decodeFn       = codecFactory.UniversalDeserializer().Decode
	useSubprocess  bool
	clickhouseAddr string
)

func init() {
	utilruntime.Must(corev1alpha.Install(rs))

	devCmd.PersistentFlags().
		BoolVar(&useSubprocess, "use-subprocess", false, "Use subprocess for apiserver and backplane.")
	devCmd.PersistentFlags().
		StringVar(&clickhouseAddr, "clickhouse-addr", "", "ClickHouse address (host only, port 9000 will be used).")
	RootCmd.AddCommand(devCmd)
}

func maybeNamespaced(un *unstructured.Unstructured) string {
	ns := un.GetNamespace()
	if ns == "" {
		return un.GetName()
	}
	return fmt.Sprintf("%s/%s", ns, un.GetName())
}

func updateFromFile(ctx context.Context, proxyNameOverride, path string) error {
	cfg, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	c, err := config.DefaultAPIClient()
	if err != nil {
		return err
	}

	dc, err := discovery.NewDiscoveryClientForConfig(c.RESTConfig)
	if err != nil {
		return err
	}
	dynClient, err := dynamic.NewForConfig(c.RESTConfig)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

	for _, objYaml := range strings.Split(string(cfg), "\n---\n") {
		if strings.TrimSpace(objYaml) == "" {
			continue
		}

		unObj := &unstructured.Unstructured{}
		_, _, err := decodeFn([]byte(objYaml), nil, unObj)
		if err != nil {
			return fmt.Errorf("failed to decode object: %w", err)
		}

		mapping, err := mapper.RESTMapping(
			unObj.GroupVersionKind().GroupKind(),
			unObj.GroupVersionKind().Version,
		)
		if err != nil {
			return err
		}

		log.Debugf("Creating object gvk=%v name=%s", unObj.GroupVersionKind(), maybeNamespaced(unObj))

		if unObj.GetKind() == "Proxy" {
			unObj.SetName(proxyNameOverride)
		} else if unObj.GetKind() == "Gateway" {
			// Override .spec.infrastructure.parametersRef.name to proxy name.
			if err := unstructured.SetNestedField(
				unObj.Object,
				proxyNameOverride,
				"spec", "infrastructure", "parametersRef", "name",
			); err != nil {
				return fmt.Errorf("failed to set .spec.infrastructure.parametersRef.name: %w", err)
			}
		}

		_, err = dynClient.Resource(mapping.Resource).
			Namespace(unObj.GetNamespace()).
			Create(ctx, unObj, metav1.CreateOptions{})
		if k8serrors.IsAlreadyExists(err) {
			log.Debugf("Object gvk=%v name=%s already exists, patching...", unObj.GroupVersionKind(), maybeNamespaced(unObj))

			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				data, err := runtime.Encode(
					unstructured.UnstructuredJSONScheme,
					unObj,
				)
				if err != nil {
					return err
				}

				_, err = dynClient.Resource(mapping.Resource).
					Namespace(unObj.GetNamespace()).
					Patch(ctx, unObj.GetName(), types.StrategicMergePatchType, data, metav1.PatchOptions{})
				return err
			})
			if err != nil {
				return fmt.Errorf("failed to patch object gvk=%v name=%s: %w", unObj.GroupVersionKind(), maybeNamespaced(unObj), err)
			}

			log.Debugf("Patched %v object %s\n", unObj.GroupVersionKind(), maybeNamespaced(unObj))
		} else if err != nil {
			return fmt.Errorf("failed to create object gvk=%v name=%s: %w", unObj.GroupVersionKind(), maybeNamespaced(unObj), err)
		} else {
			log.Debugf("Created object gvk=%v name=%s\n", unObj.GroupVersionKind(), maybeNamespaced(unObj))
		}
	}
	return err
}

// downloadToFile downloads the content from the given URL to the specified file path
func downloadToFile(url string, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// watchAndReloadConfig watches the given path or URL for changes and reloads the
// Apoxy configuration when changes occur. For URLs, it downloads to a temp file
// and watches that. Proxy object name will be overridden with the given value.
func watchAndReloadConfig(ctx context.Context, proxyNameOverride, pathOrURL string) error {
	isURL := false
	if _, err := url.ParseRequestURI(pathOrURL); err == nil {
		if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
			isURL = true
		}
	}

	var watchPath string
	var tempDir string

	if isURL {
		// Create temp directory to store downloaded config
		var err error
		tempDir, err = os.MkdirTemp("", "apoxy-config-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory: %w", err)
		}
		defer os.RemoveAll(tempDir)

		// Generate temp file path
		fileName := filepath.Base(pathOrURL)
		if fileName == "" || fileName == "." {
			fileName = "config.yaml"
		}
		watchPath = filepath.Join(tempDir, fileName)

		// Do initial download
		if err := downloadToFile(pathOrURL, watchPath); err != nil {
			return fmt.Errorf("failed to download config from %s: %w", pathOrURL, err)
		}

		log.Infof("Downloaded config from %s to %s", pathOrURL, watchPath)
	} else {
		watchPath = pathOrURL
	}

	if err := updateFromFile(ctx, proxyNameOverride, watchPath); err != nil {
		return fmt.Errorf("failed to apply initial configuration: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(watchPath); err != nil {
		return fmt.Errorf("failed to add file to watcher: %w", err)
	}

	fmt.Printf("Watching %s for changes...\n", watchPath)

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !ev.Has(fsnotify.Write) {
				continue
			}
			fmt.Printf("Updating proxy %s from %s...\n", proxyNameOverride, watchPath)
			// Reload the proxy configuration
			if err := updateFromFile(ctx, proxyNameOverride, watchPath); err != nil {
				return err
			}
		case <-time.After(3 * time.Second):
			// Reload the proxy configuration
			if err := updateFromFile(ctx, proxyNameOverride, watchPath); err != nil {
				return err
			}
		case err := <-watcher.Errors:
			return err
		}
	}
}

type runError struct {
	Err error
}

func (e *runError) Error() string {
	return e.Err.Error()
}

func (e *runError) Unwrap() error {
	return e.Err
}

func stopCh(ctx context.Context) <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

var devCmd = &cobra.Command{
	Use:   "dev [path/to/proxy.yaml]",
	Short: "Develop against the Apoxy API locally",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config.LocalMode = true
		cmd.SilenceUsage = true
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		projectID := uuid.New()
		if cfg.CurrentProject != uuid.Nil {
			projectID = cfg.CurrentProject
		}

		path := args[0]
		proxyName, err := os.Hostname()
		if err != nil {
			return err
		}

		fmt.Printf("Starting Apoxy server with Proxy name: %s\n", proxyName)

		ctx, ctxCancel := context.WithCancelCause(cmd.Context())
		defer ctxCancel(ctx.Err())

		driverMode := drivers.DockerMode
		if useSubprocess {
			driverMode = drivers.SupervisorMode
		}

		fmt.Printf("Starting apiserver using driver mode: %s\n", driverMode)
		apiDriver, err := drivers.GetDriver(driverMode, drivers.APIServerService)
		if err != nil {
			return err
		}
		apiserverArgs := []string{}
		tmpDir := os.Getenv("APOXY_TMPDIR")
		if tmpDir != "" {
			apiserverArgs = []string{
				fmt.Sprintf("--db=%s", filepath.Join(tmpDir, "apoxy.db")),
				fmt.Sprintf("--temporal-db=%s", filepath.Join(tmpDir, "temporal.db")),
				fmt.Sprintf("--ingest-store-dir=%s", filepath.Join(tmpDir, "ingest")),
			}
		}
		if _, err := apiDriver.Start(ctx, projectID, proxyName, drivers.WithArgs(apiserverArgs...)); err != nil {
			log.Errorf("failed to start apiserver: %v", err)
			return err
		}
		defer apiDriver.Stop(projectID, proxyName)

		if len(clickhouseAddr) == 0 {
			fmt.Printf("Starting clickhouse using driver mode: docker\n")
			chDriver, err := chdrivers.GetDriver("docker")
			if err != nil {
				return err
			}
			if err := chDriver.Start(ctx, projectID); err != nil {
				return err
			}
			clickhouseAddr, err = chDriver.GetAddr(ctx)
			if err != nil {
				return err
			}
		} else {
			fmt.Printf("clickhouse server is already running: %s\n", clickhouseAddr)
			fmt.Printf("running clickhouse migrations for project id: %s\n", projectID)
			if err := migrations.Run(clickhouseAddr+":9000", projectID); err != nil {
				return fmt.Errorf("failed to run clickhouse migrations: %w", err)
			}
		}

		fmt.Printf("Starting backplane using driver mode: %s\n", driverMode)
		bpDriver, err := drivers.GetDriver(driverMode, drivers.BackplaneService)
		if err != nil {
			return err
		}

		apiserverAddr, err := apiDriver.GetAddr(ctx)
		if err != nil {
			return fmt.Errorf("failed to get apiserver address: %v", err)
		}

		cname, err := bpDriver.Start(
			ctx,
			projectID,
			proxyName,
			drivers.WithArgs([]string{
				fmt.Sprintf("--ch_addrs=%s:9000", clickhouseAddr),
				fmt.Sprintf("--dev=%t", true),
			}...),
			drivers.WithAPIServerAddr(fmt.Sprintf("%s:8443", apiserverAddr)),
		)
		if err != nil {
			return err
		}
		defer bpDriver.Stop(projectID, proxyName)

		if !useSubprocess {
			rc := apiserver.NewClientConfig()
			fwd, err := portforward.NewPortForwarder(rc, proxyName, proxyName, cname)
			if err != nil {
				log.Errorf("failed to create port forwarder: %v", err)
				return err
			}
			go func() {
				if err := fwd.Run(ctx); err != nil {
					log.Errorf("failed to forward ports: %v", err)
					ctxCancel(&runError{Err: err})
				}
				// If err is nil, it means context has been cancelled.
			}()
		}

		fmt.Printf("Starting tunnelproxy using driver mode: %s\n", driverMode)
		tpDriver, err := drivers.GetDriver(driverMode, drivers.TunnelProxyService)
		if err != nil {
			return err
		}

		if _, err := tpDriver.Start(
			ctx,
			projectID,
			proxyName,
			drivers.WithAPIServerAddr(fmt.Sprintf("%s:8443", apiserverAddr)),
		); err != nil {
			return err
		}
		defer tpDriver.Stop(projectID, proxyName)

		if err := watchAndReloadConfig(ctx, proxyName, path); err != nil {
			return err
		}
		go func() {
			<-cmd.Context().Done()
			fmt.Printf("\r") // Clear the ^C
			fmt.Printf("Caught interrupt, shutting down...\n")
		}()
		<-ctx.Done()

		var runErr *runError
		if err := context.Cause(ctx); errors.As(err, &runErr) {
			return runErr.Err
		}

		return nil
	},
}
