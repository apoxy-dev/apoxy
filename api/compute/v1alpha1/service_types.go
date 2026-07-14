package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// =============================================================================
// Runtime, bindings, modes.
// =============================================================================

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// BindingType discriminates the Binding union.
type BindingType string

const (
	SecretBindingType  BindingType = "secret"
	KVBindingType      BindingType = "kv"
	ServiceBindingType BindingType = "service"
)

// Binding grants a platform resource capability to the service (secrets, KV,
// service-to-service): a service reaches no platform resource it isn't
// explicitly bound to. Outbound network access is NOT a binding — it is
// governed by the egress block (see ServiceEgress) and is on by default via
// the project's default gateway.
type Binding struct {
	// Name is the identifier exposed to service code (env.<Name>).
	Name string      `json:"name"`
	Type BindingType `json:"type"`

	// +optional
	Secret *SecretBinding `json:"secret,omitempty"`
	// +optional
	KV *KVBinding `json:"kv,omitempty"`
	// +optional
	Service *ServiceBinding `json:"service,omitempty"`
	// Future: Queue, DurableObject, R2/S3-style object store.
}

// SecretBinding exposes one key of a core.apoxy.dev SecretStore to service
// code as env.<Binding.Name>. The store's scopes must admit this service
// (surface "compute"). The value is resolved at worker materialization time
// and never enters the bundle or the revision.
type SecretBinding struct {
	// Store names the SecretStore (cluster-scoped, same project).
	Store corev1alpha.ObjectName `json:"store"`
	// Key within the store's values map.
	Key string `json:"key"`
}

type KVBinding struct {
	// Namespace identifies the KV store partition (a store name, not a k8s namespace).
	Namespace string `json:"namespace"`
}

// ServiceBinding wires service-to-service calls (e.g. a filter Service invoking a
// backend Service) without going back out over the network. ServiceRef is
// cluster-scoped (single tenant), so no namespace.
type ServiceBinding struct {
	ServiceRef corev1alpha.ObjectName `json:"serviceRef"`
}

type ServiceLimits struct {
	// CPUTime is the per-request CPU budget (workerd-style), e.g. "50ms".
	// +optional
	CPUTime *metav1.Duration `json:"cpuTime,omitempty"`
	// Memory cap, e.g. "128Mi".
	// +optional
	Memory *string `json:"memory,omitempty"`
}

type ServiceRuntime struct {
	// CompatibilityDate is required by workerd; pinned per revision.
	CompatibilityDate string `json:"compatibilityDate"`
	// +optional
	CompatibilityFlags []string `json:"compatibilityFlags,omitempty"`
	// Timeout is the wall-clock request timeout. Default 30s.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`
	// +optional
	Limits *ServiceLimits `json:"limits,omitempty"`
}

// ServiceEgress selects how the service's outbound network traffic
// ("egress") is mediated. Egress is transparent to worker code: there is no
// binding and no fetch wrapper — a plain fetch() works, subject to the
// selected gateway's routes and default policy. Enforcement is host-side
// (sandbox netstack + egress gateway), never inside workerd.
//
// Egress is ON by default: an absent block (or an empty gatewayRef) resolves
// to the project "default" gateway, which is a built-in allow-all unless an
// EgressGateway named "default" exists (see DefaultEgressGatewayName). Set
// disabled: true to hard-deny all egress for this service.
//
// NOT YET ENFORCED: the egress control/data planes are still landing, and
// until they do the runtime denies all worker egress regardless of this
// block. The API is stable; the described semantics take effect when
// enforcement ships.
type ServiceEgress struct {
	// GatewayRef names the compute.apoxy.dev EgressGateway that mediates
	// this service's outbound traffic. Empty means the project "default"
	// gateway. Existence is not validated at admission; a dangling ref
	// surfaces as the EgressReady=False condition on Service status.
	// +optional
	GatewayRef corev1alpha.ObjectName `json:"gatewayRef,omitempty"`

	// Disabled hard-denies all egress for this service (globalOutbound is
	// unset in workerd and the sandbox netstack resets any outbound
	// attempt). Mutually exclusive with a non-empty gatewayRef.
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// ServiceMode is the service's effective runtime mode. It is not a spec field:
// the mode is derived from which ServiceConfig member is set (see
// ServiceConfig.Mode). These constants are used by controllers and status.
type ServiceMode string

const (
	// BackendMode: full fetch handler serving HTTP; referenced as a backendRef.
	// This is the default mode when no config block is set.
	BackendMode ServiceMode = "backend"
	// FilterMode: runs inline in the data path via ext_proc before/around the backend.
	FilterMode ServiceMode = "filter"
)

type FilterPhase string

const (
	RequestPhase  FilterPhase = "request"
	ResponsePhase FilterPhase = "response"
	BothPhases    FilterPhase = "both"
)

type FailureMode string

const (
	FailOpen   FailureMode = "failOpen"
	FailClosed FailureMode = "failClosed"
)

// FilterConfig configures a service running in filter mode; its presence in a
// ServiceConfig selects filter mode.
type FilterConfig struct {
	// +optional
	// +kubebuilder:default=request
	Phase FilterPhase `json:"phase,omitempty"`
	// +optional
	// +kubebuilder:default=failClosed
	FailureMode FailureMode `json:"failureMode,omitempty"`
}

type BackendProtocol string

const (
	HTTP1 BackendProtocol = "http1"
	HTTP2 BackendProtocol = "http2"
	// L4 protocols (future). The service becomes a raw listener with no L7
	// router in front. workerd is HTTP-inbound-only (its socket union is
	// http/https/tls), so these are served via Apoxy's own L4 data path, not
	// workerd sockets.
	TCP BackendProtocol = "tcp"
	UDP BackendProtocol = "udp"
)

// BackendConfig configures a service running in backend mode (the default).
//
// Protocol is the discriminator that decides whether Port is user-meaningful:
//   - http1/http2: the service is served via Envoy. The listen port is the
//     internal Envoy<->runtime contract, programmed by the controller, and is
//     NOT set here (Port is ignored). This mirrors workerd, which keeps port
//     off the Service entirely and on a separate top-level `sockets` entry.
//   - tcp/udp (future): the service is an L4 listener, so Port IS the contract
//     and the demux key. This is also the value an HTTPRoute-style backendRef
//     port would later select among, once a Service can expose multiple L4
//     listeners. For http services a backendRef should omit port (Gateway API
//     only requires it for core Services; PortNumber min=1 rejects a 0 sentinel).
type BackendConfig struct {
	// +optional
	// +kubebuilder:default=http1
	Protocol BackendProtocol `json:"protocol,omitempty"`
	// Port is only meaningful for tcp/udp; ignored for http1/http2.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *int32 `json:"port,omitempty"`
}

// ServiceConfig is the runtime-mode union. The mode is implicit in which member
// is set rather than carried in a separate discriminator field:
//   - filter set  -> filter mode
//   - backend set -> backend mode
//   - neither set -> backend mode (the default; the defaulter materializes an
//     empty backend block)
//   - both set    -> rejected by validation
type ServiceConfig struct {
	// Filter selects filter mode and its settings.
	// +optional
	Filter *FilterConfig `json:"filter,omitempty"`
	// Backend selects backend mode and its settings; this is the default mode
	// when neither member is set.
	// +optional
	Backend *BackendConfig `json:"backend,omitempty"`
}

// Mode returns the effective runtime mode implied by which member is set. Only
// an explicit filter block selects filter mode; a nil config, an empty config,
// or a backend-only config is backend mode. A config with both members set is
// invalid (rejected in validation); Mode reports it as filter and lets the
// validator surface the error.
func (c *ServiceConfig) Mode() ServiceMode {
	if c != nil && c.Filter != nil {
		return FilterMode
	}
	return BackendMode
}

// =============================================================================
// Service (serving) + ServiceRevision.
// =============================================================================

// ServiceConfigSpec is the user-owned serving configuration shared by a Service
// template and a minted ServiceRevision: the runtime-mode union plus runtime
// settings, bindings, and env. It deliberately carries NO bundle — the bundle a
// service runs always comes from spec.source resolution, never from this config.
type ServiceConfigSpec struct {
	// ServiceConfig is inlined: its variant blocks (filter / backend) appear
	// directly rather than nested under a wrapper. Exactly one of filter /
	// backend may be set; the populated block IS the mode discriminator — there
	// is no separate mode field. When neither is set the service defaults to
	// backend mode (the defaulter materializes an empty backend block), so a
	// plain backend service needs no block at all. The mode is immutable:
	// switching backend<->filter on an existing Service is rejected.
	ServiceConfig `json:",inline"`

	// +optional
	Runtime *ServiceRuntime `json:"runtime,omitempty"`
	// +optional
	Bindings []Binding `json:"bindings,omitempty"`
	// +optional
	Env []EnvVar `json:"env,omitempty"`
	// Egress selects how outbound network traffic is mediated. Absent means
	// the project "default" egress gateway (egress on by default); see
	// ServiceEgress for the full semantics and the disabled opt-out.
	// +optional
	Egress *ServiceEgress `json:"egress,omitempty"`
}

// ServiceRevisionSpec is a minted, immutable revision: a snapshot of the serving
// config plus the concrete resolved bundle. Unlike the template, Bundle is
// always present and digest-pinned — it is the artifact the data plane runs.
type ServiceRevisionSpec struct {
	ServiceConfigSpec `json:",inline"`

	// Bundle is the resolved OCI artifact this revision runs. It is always
	// digest-pinned and is set by the controller when minting the revision from
	// spec.source; it is never user-authored.
	Bundle BundleRef `json:"bundle"`
}

// ServiceTemplateSpec is Service.spec.template: the desired config for the NEXT
// minted revision. Following the Knative Service/Revision shape, it pairs
// metadata (propagated onto minted ServiceRevisions) with the bundle-less config
// spec. Editing it mints a new ServiceRevision.
type ServiceTemplateSpec struct {
	// metadata's labels/annotations propagate to minted revisions; an explicit
	// name (or generateName) controls revision naming. Namespace is rejected:
	// these kinds are cluster-scoped.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ServiceConfigSpec `json:"spec"`
}

type ServiceSpec struct {
	// Template is the desired serving config for the next minted revision.
	// Always user-owned. A change to Template mints a ServiceRevision.
	Template ServiceTemplateSpec `json:"template"`

	// Source is where the service's bundle comes from. Exactly one variant:
	// a directly-pushed OCI bundle (oci) or a git/CI pipeline (git). The resolved
	// digest always lands in the minted ServiceRevision.spec.bundle.
	Source ServiceSource `json:"source"`

	// LiveRevision selects which ServiceRevision serves:
	//   - empty: auto — the latest ready revision is served (continuous deploy
	//     for push, auto-promote for git). The served name is reported in
	//     status.liveRevision; the controller never writes this field.
	//   - set: pinned — exactly the named revision is served (rollback, or
	//     manual git promotion). New revisions are still minted but do not go
	//     live until this is repointed. The target must still be retained
	//     (see RevisionHistoryLimit).
	// +optional
	LiveRevision string `json:"liveRevision,omitempty"`

	// RevisionHistoryLimit defaults to 10.
	// +optional
	RevisionHistoryLimit *int32 `json:"revisionHistoryLimit,omitempty"`
}

type ServiceStatus struct {
	// ObservedGeneration is the most recent spec generation the controller has
	// reconciled into this status.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// LiveRevision is the ServiceRevision currently being served. When
	// spec.liveRevision is empty (auto) it tracks LatestRevision; when pinned it
	// echoes the pinned revision once that revision is actually serving.
	// +optional
	LiveRevision string `json:"liveRevision,omitempty"`
	// LatestRevision is the most recently minted ServiceRevision name. A gap
	// between this and LiveRevision means a newer revision exists but is not live
	// (a pending rollout, or a held manual promotion).
	// +optional
	LatestRevision string `json:"latestRevision,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &ServiceStatus{}

func (s *ServiceStatus) SubResourceName() string { return "status" }

func (s *ServiceStatus) CopyTo(obj resource.ObjectWithStatusSubResource) {
	switch parent := obj.(type) {
	case *Service:
		parent.Status = *s
	case *ServiceRevision:
		parent.Status = *s
	}
}

// ----- Service -----

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Service struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ServiceSpec   `json:"spec,omitempty"`
	Status            ServiceStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Service{}
	_ resource.Object                      = &Service{}
	_ resource.ObjectWithStatusSubResource = &Service{}
	_ rest.SingularNameProvider            = &Service{}
)

func (w *Service) GetObjectMeta() *metav1.ObjectMeta     { return &w.ObjectMeta }
func (w *Service) NamespaceScoped() bool                 { return false }
func (w *Service) New() runtime.Object                   { return &Service{} }
func (w *Service) NewList() runtime.Object               { return &ServiceList{} }
func (w *Service) IsStorageVersion() bool                { return true }
func (w *Service) GetSingularName() string               { return "service" }
func (w *Service) GetStatus() resource.StatusSubResource { return &w.Status }
func (w *Service) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "services",
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Service `json:"items"`
}

var _ resource.ObjectList = &ServiceList{}

func (l *ServiceList) GetListMeta() *metav1.ListMeta { return &l.ListMeta }

// ----- ServiceRevision (immutable) -----

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ServiceRevision struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ServiceRevisionSpec `json:"spec,omitempty"`
	Status            ServiceStatus       `json:"status,omitempty"`
}

var (
	_ resource.Object                      = &ServiceRevision{}
	_ resource.ObjectWithStatusSubResource = &ServiceRevision{}
	_ rest.SingularNameProvider            = &ServiceRevision{}
)

func (r *ServiceRevision) GetObjectMeta() *metav1.ObjectMeta     { return &r.ObjectMeta }
func (r *ServiceRevision) NamespaceScoped() bool                 { return false }
func (r *ServiceRevision) New() runtime.Object                   { return &ServiceRevision{} }
func (r *ServiceRevision) NewList() runtime.Object               { return &ServiceRevisionList{} }
func (r *ServiceRevision) IsStorageVersion() bool                { return true }
func (r *ServiceRevision) GetSingularName() string               { return "servicerevision" }
func (r *ServiceRevision) GetStatus() resource.StatusSubResource { return &r.Status }
func (r *ServiceRevision) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "servicerevisions",
	}
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ServiceRevisionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceRevision `json:"items"`
}

var _ resource.ObjectList = &ServiceRevisionList{}

func (l *ServiceRevisionList) GetListMeta() *metav1.ListMeta { return &l.ListMeta }
