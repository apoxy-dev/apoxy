package start

import (
	"context"
	"fmt"
	"io"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiserverapiserver "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/anonymous"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/authorization/union"
	openapinamer "k8s.io/apiserver/pkg/endpoints/openapi"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	apirest "k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"
	utilversion "k8s.io/component-base/version"
	openapicommon "k8s.io/kube-openapi/pkg/common"

	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
	builderrest "github.com/apoxy-dev/apoxy/pkg/apiserver/builder/rest"
)

// RecommendedConfigFn is a function that modifies the RecommendedConfig.
type RecommendedConfigFn func(*genericapiserver.RecommendedConfig) *genericapiserver.RecommendedConfig

// OpenAPIConfig holds OpenAPI configuration.
type OpenAPIConfig struct {
	Title   string
	Version string
	GetDefs openapicommon.GetOpenAPIDefinitions
}

// ServerOptions holds complete server configuration.
type ServerOptions struct {
	// Scheme is the runtime scheme for API types.
	Scheme *runtime.Scheme
	// Codecs is the codec factory for serialization.
	Codecs serializer.CodecFactory
	// APIs maps GroupVersionResource to storage providers.
	APIs map[schema.GroupVersionResource]builderrest.StorageProvider
	// ServingOptions configures TLS and serving.
	ServingOptions *SecureServingOptions
	// ConfigFns are callbacks to modify the recommended config.
	ConfigFns []RecommendedConfigFn
	// OpenAPI configures OpenAPI documentation.
	OpenAPI *OpenAPIConfig
	// Authenticator is the request authenticator. If nil, uses anonymous auth.
	Authenticator authenticator.Request
	// Authorizer is the request authorizer. If nil, uses always-allow.
	Authorizer authorizer.Authorizer
	// StdOut is the standard output writer.
	StdOut io.Writer
	// StdErr is the standard error writer.
	StdErr io.Writer
}

// NewServerOptions creates a new ServerOptions with defaults.
func NewServerOptions(scheme *runtime.Scheme, codecs serializer.CodecFactory) *ServerOptions {
	return &ServerOptions{
		Scheme:         scheme,
		Codecs:         codecs,
		APIs:           make(map[schema.GroupVersionResource]builderrest.StorageProvider),
		ServingOptions: NewSecureServingOptions(),
		StdOut:         os.Stdout,
		StdErr:         os.Stderr,
	}
}

// Complete fills in default values.
func (o *ServerOptions) Complete() error {
	return nil
}

// Validate checks if options are valid.
func (o *ServerOptions) Validate() []error {
	errors := []error{}
	if o.ServingOptions != nil {
		errors = append(errors, o.ServingOptions.Validate()...)
	}
	return errors
}

// Config builds the server configuration.
func (o *ServerOptions) Config() (*Config, error) {
	// Generate self-signed certs if needed
	if err := o.ServingOptions.MaybeDefaultWithSelfSignedCerts("localhost", nil, nil); err != nil {
		return nil, fmt.Errorf("failed to generate self-signed certs: %w", err)
	}

	// Create recommended config
	serverConfig := genericapiserver.NewRecommendedConfig(o.Codecs)

	// Set EffectiveVersion - required by Complete() for OpenAPI config
	serverConfig.EffectiveVersion = utilversion.NewEffectiveVersion("")

	// Apply secure serving
	if err := o.ServingOptions.ApplyTo(&serverConfig.SecureServing); err != nil {
		return nil, fmt.Errorf("failed to apply secure serving: %w", err)
	}

	// Set external address from the actual listener to prevent Complete() from calling SecureServing.HostPort()
	// This MUST be set before Complete() is called, otherwise Complete() will panic trying to derive it
	if serverConfig.SecureServing != nil && serverConfig.SecureServing.Listener != nil {
		serverConfig.ExternalAddress = serverConfig.SecureServing.Listener.Addr().String()
	} else {
		// Fallback to configured port if listener not available
		serverConfig.ExternalAddress = fmt.Sprintf("0.0.0.0:%d", o.ServingOptions.BindPort)
	}

	// Create loopback client config for internal communication
	// This is required by RecommendedConfig.Complete()
	if serverConfig.SecureServing != nil && serverConfig.SecureServing.Cert != nil {
		certBytes, _ := serverConfig.SecureServing.Cert.CurrentCertKeyContent()
		if len(certBytes) > 0 {
			serverConfig.LoopbackClientConfig = &rest.Config{
				Host: fmt.Sprintf("https://localhost:%d", o.ServingOptions.BindPort),
				TLSClientConfig: rest.TLSClientConfig{
					CAData: certBytes,
				},
				BearerToken: "loopback-token",
			}
		}
	}
	// Fallback: create minimal loopback config if cert not available yet
	if serverConfig.LoopbackClientConfig == nil {
		serverConfig.LoopbackClientConfig = &rest.Config{
			Host: fmt.Sprintf("https://localhost:%d", o.ServingOptions.BindPort),
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true,
			},
		}
	}

	// Configure authentication
	if o.Authenticator != nil {
		serverConfig.Authentication.Authenticator = o.Authenticator
	} else {
		// Default: allow anonymous access (empty conditions = all requests allowed)
		serverConfig.Authentication.Authenticator = anonymous.NewAuthenticator([]apiserverapiserver.AnonymousAuthCondition{})
	}

	// Configure authorization
	if o.Authorizer != nil {
		serverConfig.Authorization.Authorizer = o.Authorizer
	} else {
		// Default: privileged groups can do anything, deny all others
		serverConfig.Authorization.Authorizer = union.New(
			authorizerfactory.NewPrivilegedGroups(user.SystemPrivilegedGroup),
			authorizerfactory.NewAlwaysDenyAuthorizer(),
		)
	}

	// Configure OpenAPI
	if o.OpenAPI != nil {
		serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(
			o.OpenAPI.GetDefs,
			openapinamer.NewDefinitionNamer(o.Scheme),
		)
		serverConfig.OpenAPIConfig.Info.Title = o.OpenAPI.Title
		serverConfig.OpenAPIConfig.Info.Version = o.OpenAPI.Version
		serverConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(
			o.OpenAPI.GetDefs,
			openapinamer.NewDefinitionNamer(o.Scheme),
		)
		serverConfig.OpenAPIV3Config.Info.Title = o.OpenAPI.Title
		serverConfig.OpenAPIV3Config.Info.Version = o.OpenAPI.Version
	}

	// Apply config functions
	for _, fn := range o.ConfigFns {
		serverConfig = fn(serverConfig)
	}

	// Disable flow control
	serverConfig.FlowControl = nil

	return &Config{
		GenericConfig: serverConfig,
		ExtraConfig: ExtraConfig{
			Scheme: o.Scheme,
			Codecs: o.Codecs,
			APIs:   o.APIs,
		},
	}, nil
}

// Config holds completed server configuration.
type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

// ExtraConfig holds additional configuration specific to this server.
type ExtraConfig struct {
	Scheme *runtime.Scheme
	Codecs serializer.CodecFactory
	APIs   map[schema.GroupVersionResource]builderrest.StorageProvider
}

// Complete fills in any fields not set.
func (c *Config) Complete() CompletedConfig {
	return CompletedConfig{Config: c}
}

// CompletedConfig is a completed Config ready for use.
type CompletedConfig struct {
	*Config
}

// ApoxyServer is the API server.
type ApoxyServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

// New creates a new ApoxyServer from the completed config.
func (c CompletedConfig) New() (*ApoxyServer, error) {
	genericServer, err := c.GenericConfig.Complete().New("apoxy-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	s := &ApoxyServer{
		GenericAPIServer: genericServer,
	}

	// Install API groups
	if err := s.installAPIGroups(c.ExtraConfig); err != nil {
		return nil, err
	}

	return s, nil
}

// installAPIGroups installs all API groups.
func (s *ApoxyServer) installAPIGroups(extraConfig ExtraConfig) error {
	// First, group resources by API Group, then by Version
	// This ensures all versions of the same group are installed together
	byGroup := make(map[string]map[schema.GroupVersion]map[string]builderrest.StorageProvider)
	for gvr, sp := range extraConfig.APIs {
		gv := gvr.GroupVersion()
		if byGroup[gv.Group] == nil {
			byGroup[gv.Group] = make(map[schema.GroupVersion]map[string]builderrest.StorageProvider)
		}
		if byGroup[gv.Group][gv] == nil {
			byGroup[gv.Group][gv] = make(map[string]builderrest.StorageProvider)
		}
		byGroup[gv.Group][gv][gvr.Resource] = sp
	}

	// Create and install each API group with all its versions
	for group, versions := range byGroup {
		apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(group, extraConfig.Scheme, runtime.NewParameterCodec(extraConfig.Scheme), extraConfig.Codecs)

		for gv, resources := range versions {
			storage := make(map[string]apirest.Storage)
			for resourceName, sp := range resources {
				restStorage, err := sp.ResourceStorage(extraConfig.Scheme, nil) // TODO: RESTOptionsGetter
				if err != nil {
					return fmt.Errorf("failed to create storage for %s: %w", resourceName, err)
				}
				storage[resourceName] = restStorage

				// Check if resource supports status subresource
				if objAware, ok := sp.(builderrest.ObjectAwareStorageProvider); ok {
					if statusObj, ok := objAware.GetObject().(resource.ObjectWithStatusSubResource); ok {
						store, ok := restStorage.(*genericregistry.Store)
						if ok {
							statusStorage := &builderrest.StatusREST{
								Store: store,
								Obj:   statusObj,
							}
							storage[resourceName+"/status"] = statusStorage
						}
					}
				}
			}

			apiGroupInfo.VersionedResourcesStorageMap[gv.Version] = storage
		}

		if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
			return fmt.Errorf("failed to install API group %s: %w", group, err)
		}
	}

	return nil
}

// RunServer starts the API server and blocks until the context is cancelled.
func (o *ServerOptions) RunServer(ctx context.Context) error {
	config, err := o.Config()
	if err != nil {
		return fmt.Errorf("failed to build config: %w", err)
	}

	server, err := config.Complete().New()
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	prepared := server.GenericAPIServer.PrepareRun()

	return prepared.RunWithContext(ctx)
}
