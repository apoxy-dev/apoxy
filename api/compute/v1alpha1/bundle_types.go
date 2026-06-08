package v1alpha1

import (
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// =============================================================================
// OCI bundle: the interface between "build" and "serve".
// =============================================================================

const (
	// ServiceBundleConfigMediaType is the OCI config blob: a JSON-encoded
	// BundleManifest describing modules, bindings, and workerd compat.
	ServiceBundleConfigMediaType = "application/vnd.apoxy.dev.service.config.v1+json"
	// ServiceBundleModuleLayerMediaType carries executable modules (JS/Wasm).
	ServiceBundleModuleLayerMediaType = "application/vnd.apoxy.dev.service.modules.v1.tar+gzip"
	// ServiceBundleAssetsLayerMediaType carries static assets served via disk-backed services.
	ServiceBundleAssetsLayerMediaType = "application/vnd.apoxy.dev.service.assets.v1.tar+gzip"
)

// OCICredentials are inline registry credentials. Password is write-only.
type OCICredentials struct {
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	PasswordData []byte `json:"passwordData,omitempty"`
}

// OCICredentialsRef references a Secret (or equivalent) holding pull
// credentials. Namespace is retained here (unlike intra-group refs) because
// on-prem this points at a real Kubernetes Secret, which may be namespaced
// even though our own CRDs are cluster-scoped.
type OCICredentialsRef struct {
	Group     corev1alpha.Group      `json:"group"`
	Kind      corev1alpha.Kind       `json:"kind"`
	Name      corev1alpha.ObjectName `json:"name"`
	Namespace corev1alpha.Namespace  `json:"namespace"`
}

// BundleRef points at an OCI artifact containing a service bundle. Digest is
// preferred and is what controllers pin; Tag is a convenience for humans/CLI.
type BundleRef struct {
	// Repo is the OCI repository, e.g. "registry.apoxy.dev/acme/api".
	Repo string `json:"repo"`
	// Digest pins the exact artifact, e.g. "sha256:...". Strongly preferred:
	// the serving path is digest-addressed and immutable.
	// +optional
	Digest string `json:"digest,omitempty"`
	// Tag is resolved to a Digest by the controller if Digest is unset.
	// +optional
	// +kubebuilder:default="latest"
	Tag string `json:"tag,omitempty"`

	// Only one of Credentials or CredentialsRef may be set.
	// +optional
	Credentials *OCICredentials `json:"credentials,omitempty"`
	// +optional
	CredentialsRef *OCICredentialsRef `json:"credentialsRef,omitempty"`
}

// ModuleType mirrors workerd's module union.
type ModuleType string

const (
	ESModule       ModuleType = "esModule"
	CommonJSModule ModuleType = "commonJsModule"
	TextModule     ModuleType = "text"
	DataModule     ModuleType = "data"
	JSONModule     ModuleType = "json"
	WasmModule     ModuleType = "wasm"
)

// Module is one entry in the service's flat module namespace. The first esModule
// is the entrypoint. These map 1:1 onto workerd capnp `modules` entries.
type Module struct {
	Name string     `json:"name"`
	Type ModuleType `json:"type"`
	// Path within the modules layer of the bundle.
	Path string `json:"path"`
}

// BundleManifest is the on-disk schema embedded as the OCI config blob. It is
// NOT a stored API object; the builder emits it and the data plane reads it to
// reconstruct a workerd config. Kept here so build and serve agree on a schema.
type BundleManifest struct {
	Modules           []Module `json:"modules"`
	CompatibilityDate string   `json:"compatibilityDate"`
	// +optional
	CompatibilityFlags []string `json:"compatibilityFlags,omitempty"`
	// AssetsPrefix, if set, indicates a disk-backed static service mounted here.
	// +optional
	AssetsPrefix string `json:"assetsPrefix,omitempty"`
}
