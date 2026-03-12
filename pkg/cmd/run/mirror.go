package run

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/controllers"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

func runKubeMirror(ctx context.Context, cfg *configv1alpha1.Config, mc *configv1alpha1.KubeMirrorConfig) error {
	log.Infof("Starting kube-mirror component (cluster=%s, mirror=%s, namespace=%s)",
		mc.ClusterName, mc.Mirror, mc.Namespace)

	kCluster, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to create in-cluster config: %w", err)
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(gwapiv1.Install(scheme))
	utilruntime.Must(gwapiv1alpha2.Install(scheme))

	mgr, err := ctrl.NewManager(kCluster, withLeaderElection(ctrl.Options{
		Scheme: scheme,
	}, "kube-mirror", mc.Namespace, mc.ClusterName))
	if err != nil {
		return fmt.Errorf("failed to create controller manager: %w", err)
	}

	apoxyClient, err := versioned.NewForConfig(kCluster)
	if err != nil {
		return fmt.Errorf("failed to create Apoxy client: %w", err)
	}

	reconciler := controllers.NewMirrorReconciler(mgr.GetClient(), apoxyClient, mc)
	if err := reconciler.SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("failed to setup mirror reconciler: %w", err)
	}

	return mgr.Start(ctx)
}
