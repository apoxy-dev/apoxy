package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/grpc/grpclog"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8srest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/rest"
)

var (
	ConfigFile      string
	AlsoLogToStderr bool
	Verbose         bool
	ProjectID       string
	LocalMode       bool
	PprofEnabled    bool

	DefaultConfig = &configv1alpha1.Config{
		DashboardURL: "https://dashboard.apoxy.dev",
		Projects: []configv1alpha1.Project{{
			APIBaseURL: "https://api.apoxy.dev",
		}},
	}

	codec runtime.Codec
)

func init() {
	scheme := runtime.NewScheme()
	utilruntime.Must(configv1alpha1.Install(scheme))
	s := json.NewYAMLSerializer(json.DefaultMetaFactory, scheme, scheme)
	codec = serializer.NewCodecFactory(scheme).CodecForVersions(s, s, configv1alpha1.SchemeGroupVersion, configv1alpha1.SchemeGroupVersion)
}

type UnversionedConfig struct {
	// The API key to use for authentication.
	APIKey string `yaml:"api_key,omitempty"`
	// The project ID to use for authentication.
	ProjectID uuid.UUID `yaml:"project_id,omitempty"`
	// Whether to enable verbose logging.
	Verbose bool `yaml:"verbose,omitempty"`
	// The base URL for API requests.
	APIBaseURL string `yaml:"api_base_url,omitempty"`
	// The host header to set for API requests.
	APIBaseHost string `yaml:"api_base_host,omitempty"`
	// The URL for the dashboard UI.
	DashboardURL string `yaml:"dashboard_url,omitempty"`
}

// ApoxyDir returns the path to the Apoxy configuration directory.
func ApoxyDir() string {
	return filepath.Join(os.Getenv("HOME"), ".apoxy")
}

func getDefaultConfigPath() string {
	return filepath.Join(ApoxyDir(), "config.yaml")
}

func Load() (*configv1alpha1.Config, error) {
	if ConfigFile == "" {
		ConfigFile = getDefaultConfigPath()
	}

	if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
		return applyFlagOverrides(DefaultConfig)
	}

	yamlFile, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %w", err)
	}

	m := map[string]any{}
	if err := yaml.Unmarshal(yamlFile, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	_, versioned := m["apiVersion"]

	var cfg *configv1alpha1.Config
	if !versioned {
		var uc UnversionedConfig
		if err := yaml.Unmarshal(yamlFile, &uc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal unversioned config: %w", err)
		}

		cfg = &configv1alpha1.Config{
			Verbose:      uc.Verbose,
			DashboardURL: uc.DashboardURL,
		}

		if uc.ProjectID != uuid.Nil {
			cfg.CurrentProject = uc.ProjectID
			cfg.Projects = append(cfg.Projects, configv1alpha1.Project{
				ID:          uc.ProjectID,
				APIKey:      uc.APIKey,
				APIBaseURL:  uc.APIBaseURL,
				APIBaseHost: uc.APIBaseHost,
			})
		}
	} else {
		obj, gvk, err := codec.Decode(yamlFile, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decode config: %w", err)
		}

		// TODO (dpeckett): add migration logic when config schema changes.

		var ok bool
		cfg, ok = obj.(*configv1alpha1.Config)
		if !ok {
			return nil, fmt.Errorf("unrecognized config version: %v", gvk)
		}
	}

	return applyFlagOverrides(cfg)
}

func applyFlagOverrides(cfg *configv1alpha1.Config) (*configv1alpha1.Config, error) {
	// Flag overrides.
	if ProjectID != "" {
		projectID, err := uuid.Parse(ProjectID)
		if err != nil {
			return nil, fmt.Errorf("invalid project ID: %w", err)
		}
		cfg.CurrentProject = projectID
	}
	if LocalMode {
		cfg.IsLocalMode = true
	}

	var lOpts []log.Option
	if AlsoLogToStderr {
		lOpts = append(lOpts, log.WithAlsoLogToStderr())
	}

	grpclog.SetLoggerV2(grpclog.NewLoggerV2(
		log.NewDefaultLogWriter(log.InfoLevel),
		log.NewDefaultLogWriter(log.WarnLevel),
		log.NewDefaultLogWriter(log.ErrorLevel),
	))
	if Verbose || cfg.Verbose {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		slog.SetDefault(logger)
		klog.SetSlogLogger(logger)
		lOpts = append(lOpts, log.WithLevel(log.DebugLevel), log.WithDevMode())
	} else {
		klog.SetOutput(log.NewDefaultLogWriter(log.InfoLevel))
		klog.LogToStderr(false)
		lOpts = append(lOpts, log.WithLevel(log.InfoLevel))
	}

	log.Init(lOpts...)

	return cfg, nil
}

func ensureDirExists(filePath string) error {
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// Create the directory if it doesn't exist
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}
	return nil
}

func Store(cfg *configv1alpha1.Config) error {
	if ConfigFile == "" {
		ConfigFile = getDefaultConfigPath()
	}
	if err := ensureDirExists(ConfigFile); err != nil {
		return fmt.Errorf("failed to ensure directory exists: %w", err)
	}

	f, err := os.OpenFile(ConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if err := codec.Encode(cfg, f); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// DefaultAPIClient returns a new Apoxy API client.
func DefaultAPIClient() (*rest.APIClient, error) {
	if LocalMode {
		apiServerHost := "localhost"
		if os.Getenv("APOXY_API_SERVER_HOST") != "" {
			apiServerHost = os.Getenv("APOXY_API_SERVER_HOST")
		}
		return rest.NewAPIClient(
			rest.WithBaseURL("https://"+apiServerHost+":8443"),
			rest.WithBaseHost(apiServerHost),
			rest.WithProjectID(uuid.New()),
		)
	}

	cfg, err := Load()
	if err != nil {
		return nil, err
	}

	if cfg.CurrentProject == uuid.Nil {
		return nil, fmt.Errorf("project ID not set")
	}

	idx := slices.IndexFunc(cfg.Projects, func(p configv1alpha1.Project) bool {
		return p.ID == cfg.CurrentProject
	})
	if idx == -1 {
		return nil, fmt.Errorf("project not found: %s", cfg.CurrentProject)
	}
	project := cfg.Projects[idx]

	if project.KubernetesConfig != nil {
		var restConfig *k8srest.Config
		if project.KubernetesConfig.InCluster {
			restConfig, err = k8srest.InClusterConfig()
			if err != nil {
				return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
			}
		} else {
			kcPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")
			if project.KubernetesConfig.KubeconfigPath != "" {
				kcPath = project.KubernetesConfig.KubeconfigPath
			}
			config, err := clientcmd.LoadFromFile(kcPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
			}

			curContext := config.CurrentContext
			if project.KubernetesConfig.Context != "" {
				curContext = project.KubernetesConfig.Context
			}

			restConfig, err = clientcmd.NewNonInteractiveClientConfig(
				*config,
				curContext,
				&clientcmd.ConfigOverrides{},
				nil,
			).ClientConfig()
			if err != nil {
				return nil, fmt.Errorf("failed to create client config: %w", err)
			}
		}

		return rest.NewAPIClient(rest.WithK8sConfig(restConfig))
	}

	return rest.NewAPIClient(
		rest.WithBaseURL(project.APIBaseURL),
		rest.WithBaseHost(project.APIBaseHost),
		rest.WithAPIKey(project.APIKey),
		rest.WithProjectID(project.ID),
	)
}
