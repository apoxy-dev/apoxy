package v1alpha1

import (
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"

	v1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type SourceFile struct {
	// Path is the path to the source file.
	Path string `json:"path"`

	// Content is the content of the source file.
	Content string `json:"content"`
}

type JavaScriptAssetsSource struct {
	Files []SourceFile `json:"files"`
}

type JavaScriptGitSource struct {
	// Repository is the git repository URL.
	Repository string `json:"repository"`

	// Branch is the git branch.
	// +optional
	Branch string `json:"branch,omitempty"`

	// Commit is the git commit.
	// +optional
	Commit string `json:"commit,omitempty"`
}

type JavaScriptNpmSource struct {
	// Package is the npm package name.
	Package string `json:"package"`

	// Version is the npm package version.
	// +optional
	Version string `json:"version,omitempty"`
}

// JavaScriptSource provides sources for the JavaScript function runtime.
// Only one of the fields may be specified.
type JavaScriptSource struct {
	// Entrypoint is the entrypoint path to the function.
	Entrypoint string `json:"entrypoint"`

	// Asset accepts a list of source files to be included in the function.
	// Only one of Assets, Git, or Npm may be specified.
	// +optional
	Assets *JavaScriptAssetsSource `json:"assets,omitempty"`

	// Git is the git source for the function.
	// Only one of Assets, Git, or Npm may be specified.
	// +optional
	Git *JavaScriptGitSource `json:"git,omitempty"`

	// Npm is the npm source for the function.
	// Only one of Assets, Git, or Npm may be specified.
	// +optional
	Npm *JavaScriptNpmSource `json:"npm,omitempty"`
}

type WasmSource struct {
	// URL is the URL to the WebAssembly binary.
	URL string `json:"url"`
}

type OCICredentialsObjectReference struct {
	// Group is the group of the target resource.
	// Currently only controllers.apoxy.dev/v1alpha1 is supported.
	Group gwapiv1.Group `json:"group"`

	// Kind is kind of the target resource.
	// Supports Secret with on-prem deploys and
	Kind gwapiv1.Kind `json:"kind"`

	// Name is the name of the target resource.
	Name gwapiv1.ObjectName `json:"name"`
}

type OCICredentials struct {
	// Username is the username for the OCI registry.
	Username string `json:"username,omitempty"`

	// Password is the password for the OCI registry. This field is write-only
	// and is not returned in the response.
	Password string `json:"password,omitempty"`

	// PasswordData is the base64 encoded password for the OCI registry.
	PasswordData []byte `json:"passwordData,omitempty"`
}

const (
	ImageConfigMediaType = "application/vnd.apoxy.dev.image.config.v1+json"
	ImageLayerMediaType  = "application/vnd.apoxy.dev.image.content.v1.tar+gzip"
)

type OCIImageRef struct {
	// Repo is the repository of the OCI image.
	Repo string `json:"repo"`

	// Tag is the tag of the OCI image.
	// +optional
	// +kubebuilder:default="latest"
	Tag string `json:"tag"`

	// Credentials is the credentials for pulling the OCI image.
	// Only one of Credentials or CredentialsRef may be specified.
	// +optional
	Credentials *OCICredentials `json:"credentials,omitempty"`

	// CredentialsRef is the reference to the secret containing the credentials for pulling the OCI image.
	// Only one of Credentials or CredentialsRef may be specified.
	// +optional
	CredentialsRef *OCICredentialsObjectReference `json:"credentialsRef,omitempty"`
}

type GoPluginSource struct {
	// URL is the URL to the Go plugin .so
	// +optional
	URL *string `json:"url"`

	// OCI is the OCI image reference to the Go plugin.
	// +optional
	OCI *OCIImageRef `json:"oci,omitempty"`

	// PluginConfig is the configuration passed to the Go plugin as JSON-encoded
	// structpb.Struct message. Plugin will receive it as anypb.Any message.
	// +optional
	PluginConfig string `json:"pluginConfig,omitempty"`
}

type EdgeFunctionCodeSource struct {
	// Metadata of the function source.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// JsSource specifies sources for the JavaScript function runtime.
	// If set/modified, a function will undergo a build step to compile the
	// JavaScript source into a WebAssembly binary before it is deployed.
	// +optional
	JsSource *JavaScriptSource `json:"jsSource,omitempty"`

	// WasmSource specifies sources for the WebAssembly function runtime.
	// +optional
	WasmSource *WasmSource `json:"wasmSource,omitempty"`

	// GoSource specifies sources for the Go filter plugin.
	// This option is only available for non-cloud (kubernets, unmanaged, etc)
	// Proxy providers.
	// +optional
	GoPluginSource *GoPluginSource `json:"goPluginSource,omitempty"`
}

type EnvVar struct {
	// Name of the environment variable.
	Name string `json:"name"`

	// Value of the environment variable.
	Value string `json:"value"`
}

type RuntimeCapabilities struct {
	// FetchAPI is the capability to fetch data from the internet.
	// Defaults to true.
	// +optional
	FetchAPI *bool `json:"fetchAPI,omitempty"`

	// K/V is the capability to access the key/value store.
	// Defaults to true.
	// +optional
	KV *bool `json:"kv,omitempty"`
}

type EdgeFunctionRuntime struct {
	// Timeout is the maximum time the function is allowed to run.
	// Defaults to 30 seconds but can be increased depending on your plan.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Capabilities is the list of capabilities granted to the function.
	// +optional
	Capabilities *RuntimeCapabilities `json:"capabilities,omitempty"`

	// Port is the port the function listens on.
	// Defaults to 8080.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=8080
	// +optional
	Port *int32 `json:"port,omitempty"`
}

type EdgeFunctionTargetReference struct {
	// Group is the group of the target resource.
	// Currently only controllers.apoxy.dev/v1alpha1 is supported.
	Group gwapiv1.Group `json:"group"`

	// Kind is kind of the target resource.
	// Currently only Proxy is supported.
	Kind gwapiv1.Kind `json:"kind"`

	// Name is the name of the target resource.
	Name gwapiv1.ObjectName `json:"name"`
}

type EdgeFunctionMode string

const (
	// BackendEdgeFunctionMode means the function is used as a backend.
	BackendEdgeFunctionMode EdgeFunctionMode = "backend"

	// FilterEdgeFunctionMode means the function is used as a filter - a function
	// will be executed before the request is sent to the backend. This improves
	// performance by reducing the number of requests sent to the backend.
	FilterEdgeFunctionMode EdgeFunctionMode = "filter"
)

type EdgeFunctionSpec struct {
	// Mode is runtime mode of the function.
	Mode EdgeFunctionMode `json:"mode"`

	// Code is the source of the function code/binary.
	Code EdgeFunctionCodeSource `json:"code"`

	// Env is a list of environment variables to set in the function
	// runtime.
	// These will be available via WASIp1 environ* routines as well as Apoxy Runtime SDK APIs.
	// +optional
	Env []EnvVar `json:"env,omitempty"`

	// Configuration for the function runtime.
	// +optional
	Runtime *EdgeFunctionRuntime `json:"runtime,omitempty"`
}

type EdgeFunctionStatus struct {
	// LiveRevision is the revision of the function that is currently being served
	// referenced by EdgeFunctionRevision object name.
	// +optional
	LiveRevision string `json:"liveRevision,omitempty"`

	// Conditions describe the current conditions of the EdgeFunction.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &EdgeFunctionStatus{}

func (ps *EdgeFunctionStatus) SubResourceName() string {
	return "status"
}

func (ps *EdgeFunctionStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	parent, ok := obj.(*EdgeFunction)
	if ok {
		parent.Status = *ps
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EdgeFunction struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EdgeFunctionSpec   `json:"spec,omitempty"`
	Status EdgeFunctionStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &EdgeFunction{}
	_ resource.Object                      = &EdgeFunction{}
	_ resource.ObjectWithStatusSubResource = &EdgeFunction{}
	_ rest.SingularNameProvider            = &EdgeFunction{}
)

func (p *EdgeFunction) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *EdgeFunction) NamespaceScoped() bool {
	return false
}

func (p *EdgeFunction) New() runtime.Object {
	return &EdgeFunction{}
}

func (p *EdgeFunction) NewList() runtime.Object {
	return &EdgeFunctionList{}
}

func (p *EdgeFunction) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "edgefunctions",
	}
}

func (p *EdgeFunction) IsStorageVersion() bool {
	return false
}

func (p *EdgeFunction) GetSingularName() string {
	return "edgefunction"
}

func (p *EdgeFunction) GetStatus() resource.StatusSubResource {
	return &p.Status
}

var _ resource.MultiVersionObject = &EdgeFunction{}

func (p *EdgeFunction) NewStorageVersionObject() runtime.Object {
	return &v1alpha2.EdgeFunction{}
}

func (p *EdgeFunction) ConvertToStorageVersion(storageObj runtime.Object) error {
	obj, ok := storageObj.(*v1alpha2.EdgeFunction)
	if !ok {
		return errors.New("failed to convert to v1alpha2 EdgeFunction")
	}

	obj.ObjectMeta = *p.ObjectMeta.DeepCopy()
	tmpl, err := convertSpecFromV1Alpha1ToV1Alpha2(&p.Spec)
	if err != nil {
		return err
	}
	obj.Spec.Template = *tmpl

	obj.Status = *convertEdgeFunctionStatusFromV1Alpha1ToV1Alpha2(&p.Status)

	return nil
}

func (p *EdgeFunction) ConvertFromStorageVersion(storageObj runtime.Object) error {
	obj, ok := storageObj.(*v1alpha2.EdgeFunction)
	if !ok {
		return errors.New("failed to convert from v1alpha2 EdgeFunction")
	}

	p.ObjectMeta = *obj.ObjectMeta.DeepCopy()
	spec, err := convertSpecFromV1Alpha2ToV1Alpha1(&obj.Spec.Template)
	if err != nil {
		return err
	}
	p.Spec = *spec

	p.Status = *convertEdgeFunctionStatusFromV1Alpha2ToV1Alpha1(&obj.Status)

	return nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EdgeFunctionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeFunction `json:"items"`
}

var _ resource.ObjectList = &EdgeFunctionList{}

func (pl *EdgeFunctionList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
