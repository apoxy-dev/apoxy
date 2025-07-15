package main

import (
	"flag"
	"os"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiregistration"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiserviceproxy"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

var (
	projectID = flag.String("project_id", "", "Project ID.")

	// One of these must be set.
	bootstrapToken = flag.String("bootstrap_token", os.Getenv("APOXY_BOOTSTRAP_TOKEN"), "Token to bootstrap for Apoxy Cloud.")
	kubeconfigPath = flag.String("kubeconfig_path", "", "Path to kubeconfig file for a cluster to bootstrap against.")

	clusterName = flag.String("cluster_name", "", "Name of the cluster (can be used as Location in Proxy and other objects' specs).")
	namespace   = flag.String("namespace", os.Getenv("POD_NAMESPACE"), "Namespace to watch for Proxy resources.")
	svcName     = flag.String("service_name", "kube-controller", "Name of the service to register.")

	devMode  = flag.Bool("dev", false, "Enable development mode.")
	logLevel = flag.String("log_level", "info", "Log level.")
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(discoveryv1.AddToScheme(scheme))
	utilruntime.Must(gwapiv1.AddToScheme(scheme))
	utilruntime.Must(corev1alpha.AddToScheme(scheme))
}

func main() {
	ctx := ctrl.SetupSignalHandler()

	flag.Parse()
	var lOpts []log.Option
	if *devMode {
		lOpts = append(lOpts, log.WithDevMode(), log.WithAlsoLogToStderr())
	} else if *logLevel != "" {
		lOpts = append(lOpts, log.WithLevelString(*logLevel))
	}
	log.Init(lOpts...)

	if *projectID == "" {
		log.Fatalf("--project_id must be set")
	}
	if *namespace == "" {
		log.Fatalf("--namespace must be set")
	}
	if *bootstrapToken == "" && *kubeconfigPath == "" {
		log.Fatalf("one of --bootstrap_token or --kubeconfig_path must be set")
	}

	log.Infof("Starting controllers...")

	kCluster, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("failed to create in-cluster config: %v", err)
	}
	kc := kubernetes.NewForConfigOrDie(kCluster)

	log.Infof("starting api service proxy")
	var proxyOpts []apiserviceproxy.Option
	if *projectID != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithProjectID(*projectID))
	}
	if *namespace != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithNamespace(*namespace))
	}
	if *clusterName != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithClusterName(*clusterName))
	}
	if *bootstrapToken != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithToken(*bootstrapToken))
	}
	if *kubeconfigPath != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithKubeconfigPath(*kubeconfigPath))
	}
	apiSvc, err := apiserviceproxy.NewAPIServiceProxy(ctx, kc, proxyOpts...)
	if err != nil {
		log.Fatalf("unable to create api service proxy: %v", err)
	}
	go func() {
		if err := apiSvc.Run(ctx); err != nil {
			log.Fatalf("unable to run api service proxy: %v", err)
		}
	}()

	apiReg, err := apiregistration.NewAPIRegistration(kCluster)
	if err != nil {
		log.Fatalf("failed to create api registration client: %v", err)
	}
	if err := apiReg.RegisterAPIServices(ctx, *svcName, *namespace, apiserviceproxy.DefaultPort, apiSvc.CABundle()); err != nil {
		log.Fatalf("failed to register api services: %v", err)
	}

	<-ctx.Done()
	log.Infof("controllers shutting down")
}
