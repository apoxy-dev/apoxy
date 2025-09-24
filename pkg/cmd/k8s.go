package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	runtimejson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/apoxy-dev/apoxy/config"
)

var (
	decoder = scheme.Codecs.UniversalDeserializer()
	encoder = runtimejson.NewYAMLSerializer(runtimejson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme)
)

func getYAML() ([]byte, error) {
	c, err := config.DefaultAPIClient()
	if err != nil {
		return nil, err
	}

	resp, err := c.SendRequest(http.MethodGet, "/v1/onboarding/k8s.yaml", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func installController(ctx context.Context, kc *rest.Config, yamlz []byte, ns string, dryRun, force bool) error {
	dc, err := discovery.NewDiscoveryClientForConfig(kc)
	if err != nil {
		return err
	}

	dynClient, err := dynamic.NewForConfig(kc)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

	drOutput := strings.Builder{}
	for _, yaml := range strings.Split(string(yamlz), "---") {
		if yaml == "" {
			continue
		}

		obj := &unstructured.Unstructured{}
		_, gvk, err := decoder.Decode([]byte(yaml), nil, obj)
		if err != nil {
			return fmt.Errorf("failed to decode YAML: %w", err)
		}

		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return fmt.Errorf("failed to get REST mapping: %w", err)
		}

		if ns != "" && gvk.Group == "" && gvk.Kind == "Namespace" {
			obj.SetName(ns)
		}

		var resource dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace { // Namespaced resource.
			if ns != "" {
				obj.SetNamespace(ns)
			}
			resource = dynClient.Resource(mapping.Resource).Namespace(obj.GetNamespace())
		} else { // Cluster-scoped resource.
			resource = dynClient.Resource(mapping.Resource)
		}

		jsonData, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		prettyGVK := obj.GroupVersionKind().String()
		if prettyGVK[0] == '/' {
			prettyGVK = "core" + prettyGVK
		}
		patchOpts := metav1.PatchOptions{
			FieldManager: "apoxy-cli",
			Force:        &force,
		}
		if dryRun {
			patchOpts.DryRun = []string{metav1.DryRunAll}
		}
		un, err := resource.Patch(ctx, obj.GetName(), types.ApplyPatchType, jsonData, patchOpts)
		if err != nil {
			return fmt.Errorf("failed to apply patch for %s (%s): %w", obj.GetName(), prettyGVK, err)
		}

		if dryRun {
			gvkEncoder := scheme.Codecs.EncoderForVersion(encoder, gvk.GroupVersion())
			yamlBytes, err := runtime.Encode(gvkEncoder, un)
			if err != nil {
				return fmt.Errorf("failed to encode YAML: %w", err)
			}
			drOutput.Write(yamlBytes) // Already has newline.
			drOutput.WriteString("---\n")
		} else {
			fmt.Printf("applied %s (%s)\n", un.GetName(), prettyGVK)
		}
	}

	if dryRun {
		fmt.Fprintf(os.Stderr, "Dry run complete.  No changes were made.\n")
		fmt.Print(drOutput.String())
	}

	return nil
}

var installK8sCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Apoxy Controller in Kubernetes",
	Long: `Install the Apoxy Controller into the target Kubernetes cluster.

This will create a new namespace and deploy the controller and supporting resources.  The controller
will automatically connect to the Apoxy API and begin managing your in-cluster Apoxy resources.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		// 1. If --kubeconfig is set, use that.
		// 2. If KUBECONFIG is set, use that.
		// 3. Otherwise, use the default path.
		kubeconfig, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			return err
		}
		if kubeconfig == "" {
			var ok bool
			kubeconfig, ok = os.LookupEnv("KUBECONFIG")
			if !ok {
				kubeconfig = clientcmd.RecommendedHomeFile
			}
		}
		kc, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to build Kubernetes config: %w", err)
		}

		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			return err
		}
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			return err
		}
		dryRun, err := cmd.Flags().GetBool("dry-run")
		if err != nil {
			return err
		}

		yamlz, err := getYAML()
		if err != nil {
			return fmt.Errorf("failed to get YAML: %w", err)
		}

		if err := installController(cmd.Context(), kc, yamlz, namespace, dryRun, force); err != nil {
			return fmt.Errorf("failed to install controller: %w", err)
		}

		return nil
	},
}

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Args:  cobra.NoArgs,
	Short: "Commands that manage Apoxy on Kubernetes",
}

func init() {
	installK8sCmd.Flags().String("kubeconfig", "", "Path to the kubeconfig file to use for Kubernetes API access")
	installK8sCmd.Flags().String("namespace", "apoxy", "The namespace to install the controller into")
	installK8sCmd.Flags().Bool("dry-run", false, "If true, only print the YAML that would be applied")
	installK8sCmd.Flags().Bool("force", false, "If true, forces value overwrites (See: https://v1-28.docs.kubernetes.io/docs/reference/using-api/server-side-apply/#conflicts)")
	k8sCmd.AddCommand(installK8sCmd)

	RootCmd.AddCommand(k8sCmd)
}
