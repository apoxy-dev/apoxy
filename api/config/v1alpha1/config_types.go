package v1alpha1

import (
	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ runtime.Object = (*Config)(nil)

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Config is the Schema for the Apoxy Backplane configuration.
type Config struct {
	metav1.TypeMeta `json:",inline"`
	// The name of this instance, if not specified the hostname of the machine
	// will be used.
	Name string `json:"name,omitempty"`
	// Whether to enable verbose logging.
	Verbose bool `json:"verbose,omitempty"`
	// The URL for the dashboard UI.
	DashboardURL string `json:"dashboardURL,omitempty"`
	// CurrentProject is the default project ID to use unless overridden.
	CurrentProject uuid.UUID `json:"currentProject,omitempty"`
	// Projects is a list of projects that this instance is managing.
	Projects []Project `json:"projects,omitempty"`
	// Runtime configures components started by `apoxy run`.
	Runtime *RuntimeConfig `json:"runtime,omitempty"`
	// IsLocalMode is the configuration for the local mode.
	IsLocalMode bool `json:"isLocalMode,omitempty"`
}

// Project is a configuration for a project.
type Project struct {
	// ID is the project ID.
	ID uuid.UUID `json:"id"`
	// The base URL for API requests.
	APIBaseURL string `json:"apiBaseURL,omitempty"`
	// The host header to set for API requests.
	APIBaseHost string `json:"apiBaseHost,omitempty"`
	// APIKey is the API key for the project.
	APIKey string `json:"apiKey"`
	// Kubernetes configuration for the project.
	// If set, overrides APIBaseURL, APIBaseHost, and APIKey.
	// +optional
	KubernetesConfig *KubernetesConfig `json:"kubernetesConfig,omitempty"`
}

// KubernetesConfig is the configuration for the Kubernetes API.
type KubernetesConfig struct {
	// The name of the kubeconfig context to use.
	// +optional
	Context string `json:"context,omitempty"`
	// The path to a kubeconfig file. If not specified, the standard kubeconfig
	// file paths will be used.
	// +optional
	KubeconfigPath string `json:"kubeconfigPath,omitempty"`
	// InCluster specifies whether the project is running in a Kubernetes cluster.
	// Context and KubeconfigPath are ignored if InCluster is true.
	// +optional
	InCluster bool `json:"inCluster,omitempty"`
}

type STUNScheme string

const (
	STUNSchemeSTUN    STUNScheme = "stun"
	STUNSchemeSTUNS   STUNScheme = "stuns"
	STUNSchemeTURN    STUNScheme = "turn"
	STUNSchemeTURNSSL STUNScheme = "turns"
)

type StunProto string

const (
	StunProtoUDP StunProto = "udp"
	StunProtoTCP StunProto = "tcp"
)

// STUNServer represent a STUN (https://datatracker.ietf.org/doc/html/rfc7064)
// or a TURN (https://datatracker.ietf.org/doc/html/rfc7065) server URIs.
type STUNServer struct {
	Scheme   STUNScheme `json:"scheme,omitempty"`
	Host     string     `json:"host,omitempty"`
	Port     int        `json:"port,omitempty"`
	Proto    StunProto  `json:"proto,omitempty"`
	Username string     `json:"username,omitempty"`
	Password string     `json:"password,omitempty"`
}

// TunnelConfig is the configuration for the tunnel.
type TunnelConfig struct {
	// Mode is the mode of the tunnel.
	Mode TunnelMode `json:"mode,omitempty"`
	// SocksPort, when running in userspace mode, is the port to listen on for
	// SOCKS5 proxy connections. If not specified it will default to 1080.
	SocksPort *int `json:"socksPort,omitempty"`
	// STUNServers is an optional list of STUN servers to use for determining the
	// external address of the tunnel node. If not specified it will default to
	// Google and Cloudflare's public STUN servers.
	STUNServers []STUNServer `json:"stunServers,omitempty"`
	// PacketCapturePath is an optional path to write packet captures to.
	// If not specified, packet sniffing will be disabled.
	// This is only available in userspace mode and intended for debugging purposes.
	PacketCapturePath string `json:"packetCapturePath,omitempty"`
}

// TunnelMode is the mode of the tunnel.
type TunnelMode string

const (
	// Use the kernel implementation of WireGuard.
	TunnelModeKernel TunnelMode = "kernel"
	// Use an unprivileged userspace implementation of WireGuard.
	TunnelModeUserspace TunnelMode = "userspace"
)

// RuntimeConfig configures components started by `apoxy run`.
type RuntimeConfig struct {
	// Components is the list of runtime components to start.
	Components []RuntimeComponent `json:"components,omitempty"`
}

// RuntimeComponentType identifies a runtime component.
type RuntimeComponentType string

const (
	// RuntimeComponentKubeMirror mirrors Kubernetes API resources to Apoxy.
	RuntimeComponentKubeMirror RuntimeComponentType = "kube-mirror"
	// RuntimeComponentTunnel runs the tunnel component.
	RuntimeComponentTunnel RuntimeComponentType = "tunnel"
)

// RuntimeComponent is a single runtime component entry.
type RuntimeComponent struct {
	// Type identifies the component.
	Type RuntimeComponentType `json:"type"`
	// KubeMirror configures the kube-mirror component.
	// +optional
	KubeMirror *KubeMirrorConfig `json:"kubeMirror,omitempty"`
	// Tunnel configures the tunnel component.
	// +optional
	Tunnel *TunnelConfig `json:"tunnel,omitempty"`
}

// MirrorMode specifies which Kubernetes API resources to mirror.
type MirrorMode string

const (
	MirrorModeGateway MirrorMode = "gateway"
	MirrorModeIngress MirrorMode = "ingress"
	MirrorModeAll     MirrorMode = "all"
)

// KubeMirrorConfig configures the kube-mirror runtime component.
type KubeMirrorConfig struct {
	// ClusterName is an identifier for this cluster used for multi-cluster deconfliction.
	ClusterName string `json:"clusterName,omitempty"`
	// Mirror specifies which K8s API resources to mirror. Defaults to "all".
	Mirror MirrorMode `json:"mirror,omitempty"`
	// Namespace to operate in. Defaults to "apoxy".
	Namespace string `json:"namespace,omitempty"`
	// BootstrapToken for Apoxy Cloud connectivity.
	BootstrapToken string `json:"bootstrapToken,omitempty"`
	// ServiceName for the K8s Service. Defaults to "kube-mirror".
	ServiceName string `json:"serviceName,omitempty"`
}
