package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiregistration"
	"github.com/apoxy-dev/apoxy/pkg/kube-controller/apiserviceproxy"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Apoxy runtime components defined in config",
	Long: `Start and monitor all runtime components specified in the config file's runtime section.

Components are defined under runtime.components in the config. Example:

  runtime:
    components:
      - type: kube-mirror
        kubeMirror:
          clusterName: "prod-us-east-1"
          mirror: "all"
          namespace: "apoxy"
      - type: tunnel
        tunnel:
          mode: "kernel"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if cfg.Runtime == nil || len(cfg.Runtime.Components) == 0 {
			return fmt.Errorf("no runtime components configured (check runtime.components in config)")
		}

		ctx := cmd.Context()
		g, ctx := errgroup.WithContext(ctx)

		for _, comp := range cfg.Runtime.Components {
			switch comp.Type {
			case configv1alpha1.RuntimeComponentKubeMirror:
				if comp.KubeMirror == nil {
					return fmt.Errorf("kube-mirror component requires kubeMirror config")
				}
				mirrorCfg := resolveKubeMirrorConfig(comp.KubeMirror)
				if err := validateKubeMirrorConfig(cfg, mirrorCfg); err != nil {
					return fmt.Errorf("invalid kube-mirror config: %w", err)
				}
				g.Go(func() error {
					return runKubeMirror(ctx, cfg, mirrorCfg)
				})
			case configv1alpha1.RuntimeComponentTunnel:
				return fmt.Errorf("tunnel runtime component not yet implemented")
			default:
				return fmt.Errorf("unknown runtime component type: %q", comp.Type)
			}
		}

		return g.Wait()
	},
}

func resolveKubeMirrorConfig(in *configv1alpha1.KubeMirrorConfig) *configv1alpha1.KubeMirrorConfig {
	out := in.DeepCopy()
	if out.Mirror == "" {
		out.Mirror = configv1alpha1.MirrorModeAll
	}
	if out.Namespace == "" {
		out.Namespace = "apoxy"
	}
	if out.ServiceName == "" {
		out.ServiceName = "kube-mirror"
	}
	return out
}

func validateKubeMirrorConfig(cfg *configv1alpha1.Config, mc *configv1alpha1.KubeMirrorConfig) error {
	switch mc.Mirror {
	case configv1alpha1.MirrorModeGateway, configv1alpha1.MirrorModeIngress, configv1alpha1.MirrorModeAll:
	default:
		return fmt.Errorf("invalid mirror mode %q: must be one of gateway, ingress, all", mc.Mirror)
	}
	if cfg.CurrentProject.String() == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("currentProject must be set in config")
	}
	return nil
}

func runKubeMirror(ctx context.Context, cfg *configv1alpha1.Config, mc *configv1alpha1.KubeMirrorConfig) error {
	log.Infof("Starting kube-mirror component (cluster=%s, mirror=%s, namespace=%s)",
		mc.ClusterName, mc.Mirror, mc.Namespace)

	kCluster, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to create in-cluster config: %w", err)
	}
	kc := kubernetes.NewForConfigOrDie(kCluster)

	var proxyOpts []apiserviceproxy.Option
	proxyOpts = append(proxyOpts, apiserviceproxy.WithProjectID(cfg.CurrentProject.String()))
	proxyOpts = append(proxyOpts, apiserviceproxy.WithNamespace(mc.Namespace))
	if mc.ClusterName != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithClusterName(mc.ClusterName))
	}
	if mc.BootstrapToken != "" {
		proxyOpts = append(proxyOpts, apiserviceproxy.WithToken(mc.BootstrapToken))
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
		if err := apiReg.RegisterAPIServices(ctx, mc.ServiceName, mc.Namespace, apiserviceproxy.DefaultPort, apiSvc.CABundle()); err != nil {
			return fmt.Errorf("failed to register API services: %w", err)
		}
		log.Infof("API services registered")
		<-ctx.Done()
		return nil
	})

	return g.Wait()
}

func init() {
	RootCmd.AddCommand(runCmd)
}
