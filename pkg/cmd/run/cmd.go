package run

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Apoxy runtime components defined in config",
	Long: `Start and monitor all runtime components specified in the config file's runtime section.

Components are defined under runtime.components in the config. Example:

  runtime:
    components:
      - type: kube-aggregation
        kubeAggregation:
          clusterName: "prod-us-east-1"
          namespace: "apoxy"
      - type: kube-mirror
        kubeMirror:
          mirror: "all"
      - type: tunnel
        tunnel:
          mode: "kernel"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if err := initRuntimeLogger(cfg); err != nil {
			return fmt.Errorf("failed to initialize runtime logger: %w", err)
		}
		if cfg.Runtime == nil || len(cfg.Runtime.Components) == 0 {
			return fmt.Errorf("no runtime components configured\n\n"+
				"Add a runtime section to your config (%s):\n\n"+
				"  runtime:\n"+
				"    components:\n"+
				"      - type: kube-aggregation\n"+
				"        kubeAggregation:\n"+
				"          clusterName: \"my-cluster\"\n"+
				"      - type: kube-mirror\n"+
				"        kubeMirror:\n"+
				"          mirror: \"gateway\"\n"+
				"      - type: tunnel\n"+
				"        tunnel:\n"+
				"          mode: \"user\"\n",
				config.ConfigFile)
		}

		ctx := cmd.Context()
		g, ctx := errgroup.WithContext(ctx)

		for _, comp := range cfg.Runtime.Components {
			switch comp.Type {
			case configv1alpha1.RuntimeComponentKubeAggregation:
				if comp.KubeAggregation == nil {
					return fmt.Errorf("kube-aggregation component requires kubeAggregation config")
				}
				aggCfg := resolveKubeAggregationConfig(comp.KubeAggregation)
				if err := validateKubeAggregationConfig(cfg, aggCfg); err != nil {
					return fmt.Errorf("invalid kube-aggregation config: %w", err)
				}
				g.Go(func() error {
					return runKubeAggregation(ctx, cfg, aggCfg)
				})
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
				if comp.Tunnel == nil {
					return fmt.Errorf("tunnel component requires tunnel config")
				}
				tunCfg := resolveTunnelConfig(comp.Tunnel)
				if err := validateTunnelConfig(cfg, tunCfg); err != nil {
					return fmt.Errorf("invalid tunnel config: %w", err)
				}
				g.Go(func() error {
					return runTunnel(ctx, cfg, tunCfg)
				})
			default:
				return fmt.Errorf("unknown runtime component type: %q", comp.Type)
			}
		}

		return g.Wait()
	},
}

func Cmd() *cobra.Command {
	return runCmd
}

func initRuntimeLogger(cfg *configv1alpha1.Config) error {
	opts := []log.Option{log.WithStderrOnly()}
	if config.Verbose || cfg.Verbose {
		opts = append(opts, log.WithDevMode(), log.WithLevel(log.DebugLevel))
	} else {
		opts = append(opts, log.WithLevel(log.InfoLevel))
	}
	return log.Init(opts...)
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

func resolveKubeAggregationConfig(in *configv1alpha1.KubeAggregationConfig) *configv1alpha1.KubeAggregationConfig {
	out := in.DeepCopy()
	if out.Namespace == "" {
		out.Namespace = "apoxy"
	}
	if out.ServiceName == "" {
		out.ServiceName = "kube-aggregation"
	}
	return out
}

func validateKubeAggregationConfig(cfg *configv1alpha1.Config, ac *configv1alpha1.KubeAggregationConfig) error {
	if cfg.CurrentProject.String() == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("currentProject must be set in config")
	}
	return nil
}
