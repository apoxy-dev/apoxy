// Package builder provides a fluent API for building an API server.
// This is inspired by sigs.k8s.io/apiserver-runtime/pkg/builder and tilt-dev/tilt-apiserver.
package builder

import (
	"context"
	"io"
	"net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	openapicommon "k8s.io/kube-openapi/pkg/common"

	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/rest"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/start"
)

// Server is the builder for constructing an API server.
type Server struct {
	// Separate schemes to avoid reflect.Type conflicts during OpenAPI generation
	apiScheme    *runtime.Scheme
	openapiScheme *runtime.Scheme

	// Scheme builders for deferred registration
	apiSchemeBuilder    runtime.SchemeBuilder
	openapiSchemeBuilder runtime.SchemeBuilder

	// Track ordered group versions for codec
	orderedGroupVersions []schema.GroupVersion

	// Storage providers by GVR
	apis map[schema.GroupVersionResource]rest.StorageProvider

	// Output streams
	stdOut io.Writer
	stdErr io.Writer

	// OpenAPI configuration
	openAPITitle   string
	openAPIVersion string
	openAPIDefs    openapicommon.GetOpenAPIDefinitions

	// Server option callbacks
	optionsFns []func(*ServerOptions) *ServerOptions
	configFns  []func(*genericapiserver.RecommendedConfig) *genericapiserver.RecommendedConfig

	// Authentication/Authorization
	authenticator authenticator.Request
	authorizer    authorizer.Authorizer

	// Flags
	disableAuth bool
	withoutEtcd bool

	// Secure serving options
	bindAddress   net.IP
	bindPort      int
	certFile      string
	keyFile       string
	generatedCert dynamiccertificates.CertKeyContentProvider
}

// ServerOptions mirrors the options structure from apiserver-runtime.
type ServerOptions struct {
	RecommendedOptions interface{} // Placeholder for compatibility
	StdOut             io.Writer
	StdErr             io.Writer
}

// NewServerBuilder creates a new Server builder.
func NewServerBuilder() *Server {
	return &Server{
		apiScheme:     runtime.NewScheme(),
		openapiScheme: runtime.NewScheme(),
		apis:          make(map[schema.GroupVersionResource]rest.StorageProvider),
	}
}

// APIServer is a package-level variable providing backward compatibility
// with the apiserver-runtime builder pattern.
var APIServer = NewServerBuilder()

// WithScheme sets the API scheme for the server.
// This should be a scheme with all API types already registered.
func (s *Server) WithScheme(scheme *runtime.Scheme) *Server {
	s.apiScheme = scheme
	return s
}

// WithResource registers a resource with default storage.
func (s *Server) WithResource(obj resource.Object) *Server {
	gvr := obj.GetGroupVersionResource()
	gv := gvr.GroupVersion()

	// Track ordered versions
	s.orderedGroupVersions = append(s.orderedGroupVersions, gv)

	// Register with both scheme builders
	s.apiSchemeBuilder.Register(resource.AddToScheme(obj))
	s.openapiSchemeBuilder.Register(resource.AddToScheme(obj))

	// Use default storage provider
	s.apis[gvr] = rest.NewStorageProviderWithFn(obj, nil)
	return s
}

// WithResourceAndStorage registers a resource with custom storage.
// This is the main method used with kine storage.
func (s *Server) WithResourceAndStorage(obj resource.Object, storeFn rest.StoreFn) *Server {
	gvr := obj.GetGroupVersionResource()
	gv := gvr.GroupVersion()

	// Track ordered versions
	s.orderedGroupVersions = append(s.orderedGroupVersions, gv)

	// Register with both scheme builders
	s.apiSchemeBuilder.Register(resource.AddToScheme(obj))
	s.openapiSchemeBuilder.Register(resource.AddToScheme(obj))

	// Use storage provider with custom StoreFn
	s.apis[gvr] = rest.NewStorageProviderWithFn(obj, storeFn)
	return s
}

// WithResourceAndStaticStorage registers a resource with a pre-created storage provider.
// This is used when storage is already created (e.g., SQLite REST storage).
func (s *Server) WithResourceAndStaticStorage(obj resource.Object, sp rest.StorageProvider) *Server {
	gvr := obj.GetGroupVersionResource()
	gv := gvr.GroupVersion()

	// Track ordered versions
	s.orderedGroupVersions = append(s.orderedGroupVersions, gv)

	// Register with both scheme builders
	s.apiSchemeBuilder.Register(resource.AddToScheme(obj))
	s.openapiSchemeBuilder.Register(resource.AddToScheme(obj))

	// Use the provided storage provider directly
	s.apis[gvr] = sp
	return s
}

// WithOpenAPIDefinitions sets OpenAPI configuration.
func (s *Server) WithOpenAPIDefinitions(title, version string, getDefs openapicommon.GetOpenAPIDefinitions) *Server {
	s.openAPITitle = title
	s.openAPIVersion = version
	s.openAPIDefs = getDefs
	return s
}

// DisableAuthorization disables authorization (allows all requests).
func (s *Server) DisableAuthorization() *Server {
	s.disableAuth = true
	return s
}

// WithoutEtcd indicates the server should not use etcd (uses provided storage).
func (s *Server) WithoutEtcd() *Server {
	s.withoutEtcd = true
	return s
}

// WithOptionsFns adds server options callbacks.
// These are called with ServerOptions during setup.
func (s *Server) WithOptionsFns(fns ...func(*ServerOptions) *ServerOptions) *Server {
	s.optionsFns = append(s.optionsFns, fns...)
	return s
}

// WithConfigFns adds config callbacks.
// These are called with RecommendedConfig during setup.
func (s *Server) WithConfigFns(fns ...func(*genericapiserver.RecommendedConfig) *genericapiserver.RecommendedConfig) *Server {
	s.configFns = append(s.configFns, fns...)
	return s
}

// WithAuthenticator sets a custom authenticator.
func (s *Server) WithAuthenticator(auth authenticator.Request) *Server {
	s.authenticator = auth
	return s
}

// WithAuthorizer sets a custom authorizer.
func (s *Server) WithAuthorizer(auth authorizer.Authorizer) *Server {
	s.authorizer = auth
	return s
}

// WithSecureServingAddress sets the bind address and port for secure serving.
func (s *Server) WithSecureServingAddress(ip net.IP, port int) *Server {
	s.bindAddress = ip
	s.bindPort = port
	return s
}

// WithServingCertFiles sets the TLS certificate files for secure serving.
func (s *Server) WithServingCertFiles(certFile, keyFile string) *Server {
	s.certFile = certFile
	s.keyFile = keyFile
	return s
}

// WithGeneratedCert sets a dynamic certificate provider for secure serving.
func (s *Server) WithGeneratedCert(cert dynamiccertificates.CertKeyContentProvider) *Server {
	s.generatedCert = cert
	return s
}

// buildCodec builds the codec with proper version priority like tilt-apiserver.
func (s *Server) buildCodec() (runtime.Codec, error) {
	registerGroupVersions := func(scheme *runtime.Scheme) error {
		groupVersions := make(map[string]sets.Set[string])
		for gvr := range s.apis {
			if groupVersions[gvr.Group] == nil {
				groupVersions[gvr.Group] = sets.New[string]()
			}
			groupVersions[gvr.Group].Insert(gvr.Version)
		}
		for g, versions := range groupVersions {
			gvs := []schema.GroupVersion{}
			for _, v := range versions.UnsortedList() {
				gvs = append(gvs, schema.GroupVersion{Group: g, Version: v})
			}
			if err := scheme.SetVersionPriority(gvs...); err != nil {
				return err
			}
		}
		for _, gv := range s.orderedGroupVersions {
			metav1.AddToGroupVersion(scheme, gv)
		}
		return nil
	}

	s.apiSchemeBuilder.Register(registerGroupVersions)
	if err := s.apiSchemeBuilder.AddToScheme(s.apiScheme); err != nil {
		return nil, err
	}

	s.openapiSchemeBuilder.Register(registerGroupVersions)
	if err := s.openapiSchemeBuilder.AddToScheme(s.openapiScheme); err != nil {
		return nil, err
	}

	codecs := serializer.NewCodecFactory(s.apiScheme)
	return codecs.LegacyCodec(s.orderedGroupVersions...), nil
}

// ToServerOptions converts the builder to start.ServerOptions.
func (s *Server) ToServerOptions() (*start.ServerOptions, error) {
	// Build codec (this also builds the schemes)
	_, err := s.buildCodec()
	if err != nil {
		return nil, err
	}

	codecs := serializer.NewCodecFactory(s.apiScheme)
	opts := start.NewServerOptions(s.apiScheme, codecs)

	// Copy storage providers
	for gvr, sp := range s.apis {
		opts.APIs[gvr] = sp
	}

	// Configure OpenAPI
	if s.openAPIDefs != nil {
		opts.OpenAPI = &start.OpenAPIConfig{
			Title:   s.openAPITitle,
			Version: s.openAPIVersion,
			GetDefs: s.openAPIDefs,
		}
	}

	// Configure authentication/authorization
	opts.Authenticator = s.authenticator
	if s.disableAuth {
		opts.Authorizer = nil // Will use always-allow
	} else {
		opts.Authorizer = s.authorizer
	}

	// Configure secure serving
	if s.bindAddress != nil {
		opts.ServingOptions.BindAddress = s.bindAddress
	}
	if s.bindPort > 0 {
		opts.ServingOptions.BindPort = s.bindPort
	}
	if s.certFile != "" && s.keyFile != "" {
		opts.ServingOptions.ServerCert.CertKey.CertFile = s.certFile
		opts.ServingOptions.ServerCert.CertKey.KeyFile = s.keyFile
	}
	if s.generatedCert != nil {
		opts.ServingOptions.ServerCert.GeneratedCert = s.generatedCert
	}

	// Apply option callbacks (for backward compatibility with apiserver-runtime)
	serverOpts := &ServerOptions{
		StdOut: opts.StdOut,
		StdErr: opts.StdErr,
	}
	for _, fn := range s.optionsFns {
		serverOpts = fn(serverOpts)
	}
	opts.StdOut = serverOpts.StdOut
	opts.StdErr = serverOpts.StdErr

	// Convert ConfigFns to start.RecommendedConfigFn
	for _, fn := range s.configFns {
		opts.ConfigFns = append(opts.ConfigFns, start.RecommendedConfigFn(fn))
	}

	return opts, nil
}

// Execute builds and runs the server.
// This blocks until the server is shut down.
func (s *Server) Execute() error {
	opts, err := s.ToServerOptions()
	if err != nil {
		return err
	}

	ctx := context.Background()
	return opts.RunServer(ctx)
}
