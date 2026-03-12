package run

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiregistration"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiserviceproxy"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

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

	apiSvc, err := apiserviceproxy.NewAPIServiceProxy(ctx, kc, proxyOpts...)
	if err != nil {
		return fmt.Errorf("failed to create API service proxy: %w", err)
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

	return g.Wait()
}
