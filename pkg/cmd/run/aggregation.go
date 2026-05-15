package run

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiregistration"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiserviceproxy"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const kubeControllerDeploymentName = "kube-controller"

func runKubeAggregation(ctx context.Context, cfg *configv1alpha1.Config, ac *configv1alpha1.KubeAggregationConfig) error {
	log.Infof("Starting kube-aggregation component (cluster=%s, namespace=%s)",
		ac.ClusterName, ac.Namespace)

	kCluster, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to create in-cluster config: %w", err)
	}
	kc := kubernetes.NewForConfigOrDie(kCluster)

	var proxyOpts []apiserviceproxy.Option
	proxyOpts = append(proxyOpts, apiserviceproxy.WithProjectID(cfg.CurrentProject.String()))
	proxyOpts = append(proxyOpts, apiserviceproxy.WithNamespace(ac.Namespace))
	proxyOpts = append(proxyOpts, apiserviceproxy.WithServiceName(ac.ServiceName))
	if ac.ClusterName != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithClusterName(ac.ClusterName))
	}
	if ac.BootstrapToken != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithToken(ac.BootstrapToken))
	}
	if ac.APIHost != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithAPIHost(ac.APIHost))
	}
	if cfg.IsLocalMode {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithLocalMode(true))
	}
	// Enable fsnotify hot-reload of the upstream cert. The watcher
	// no-ops cleanly when the Secret isn't mounted, so this is safe to
	// always pass; older onboarding manifests just continue using the
	// pod-restart rotation path.
	proxyOpts = append(proxyOpts, apiserviceproxy.WithCertDir(apiserviceproxy.DefaultCertDir))

	if ac.CertRenewInterval != nil {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithRenewInterval(ac.CertRenewInterval.Duration))
	}
	if ac.CertRenewThreshold != nil {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithRenewThreshold(ac.CertRenewThreshold.Duration))
	}

	apiSvc, err := apiserviceproxy.NewAPIServiceProxy(ctx, kc, proxyOpts...)
	if err != nil {
		return fmt.Errorf("failed to create API service proxy: %w", err)
	}

	// Build the leader-elected manager that gates the cert auto-renewer.
	// The watcher runs unconditionally on every pod (each pod's
	// in-process transport must be refreshed); only the renewer needs
	// to be a cluster-singleton so we don't issue N redundant certs
	// per cycle if kube-controller is ever scaled past one replica.
	renewMgr, err := ctrl.NewManager(kCluster, withLeaderElection(ctrl.Options{
		Scheme: runtime.NewScheme(),
		// Disable the manager's own metrics + health-probe servers —
		// the controller-runtime global Registry is already exposed
		// elsewhere in the pod, and binding 0.0.0.0:8080 here would
		// collide.
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	}, "kube-aggregation-cert-renewer", ac.Namespace, ac.ClusterName))
	if err != nil {
		return fmt.Errorf("failed to create cert-renewer manager: %w", err)
	}

	recorder := newCertRenewerRecorder(kc)
	deployRef := &corev1.ObjectReference{
		Kind:       "Deployment",
		APIVersion: "apps/v1",
		Namespace:  ac.Namespace,
		Name:       kubeControllerDeploymentName,
	}
	if err := renewMgr.Add(apiserviceproxy.NewCertRenewer(apiSvc, recorder, deployRef)); err != nil {
		return fmt.Errorf("failed to register cert renewer: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		log.Infof("Starting API service proxy")
		return apiSvc.Run(ctx)
	})

	g.Go(func() error {
		apiReg, err := apiregistration.NewAPIRegistration(kCluster)
		if err != nil {
			return fmt.Errorf("failed to create API registration client: %w", err)
		}
		if err := apiReg.RegisterAPIServices(ctx, ac.ServiceName, ac.Namespace, 443, apiSvc.CABundle()); err != nil {
			return fmt.Errorf("failed to register API services: %w", err)
		}
		log.Infof("API services registered")
		<-ctx.Done()
		return nil
	})

	g.Go(func() error { return renewMgr.Start(ctx) })

	return g.Wait()
}

// newCertRenewerRecorder wires a stand-alone Kubernetes Event broadcaster
// for the cert renewer. The leader-elected manager's own event broadcaster
// is a no-op (see leaderelection.go), so renewal Events go through this
// separate pipeline. The default broadcaster buffers up to 1000 events and
// drops on overflow — sink-side rejections (e.g. missing RBAC on events)
// are logged once by the recorder itself.
func newCertRenewerRecorder(kc kubernetes.Interface) record.EventRecorder {
	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{
		Interface: kc.CoreV1().Events(""),
	})
	return broadcaster.NewRecorder(runtime.NewScheme(), corev1.EventSource{
		Component: "kube-controller-cert-renewer",
	})
}
