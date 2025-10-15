package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CloudMonitoringIntegration configures integration with cloud monitoring and observability platforms.
type CloudMonitoringIntegration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CloudMonitoringIntegrationSpec   `json:"spec,omitempty"`
	Status CloudMonitoringIntegrationStatus `json:"status,omitempty"`
}

// CloudMonitoringIntegrationSpec defines the desired state of CloudMonitoringIntegration.
type CloudMonitoringIntegrationSpec struct {
	// Enabled indicates whether the monitoring integration is active.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// DatadogCredentials configures DataDog integration.
	// Only one of DatadogCredentials, GrafanaCredentials, or AxiomCredentials may be specified.
	// +optional
	DatadogCredentials *DatadogCredentials `json:"datadogCredentials,omitempty"`

	// GrafanaCredentials configures Grafana Cloud integration.
	// Only one of DatadogCredentials, GrafanaCredentials, or AxiomCredentials may be specified.
	// +optional
	GrafanaCredentials *GrafanaCredentials `json:"grafanaCredentials,omitempty"`

	// AxiomCredentials configures Axiom integration.
	// Only one of DatadogCredentials, GrafanaCredentials, or AxiomCredentials may be specified.
	// +optional
	AxiomCredentials *AxiomCredentials `json:"axiomCredentials,omitempty"`
}

// DatadogCredentials contains credentials for DataDog integration.
type DatadogCredentials struct {
	// APIKey is the DataDog API key.
	// This field should reference a secret in production environments.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	APIKey string `json:"apiKey"`

	// Site specifies the DataDog site to send data to.
	// Common values: datadoghq.com, datadoghq.eu, us3.datadoghq.com, us5.datadoghq.com, ddog-gov.com
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Site string `json:"site"`
}

// GrafanaCredentials contains credentials for Grafana Cloud integration.
type GrafanaCredentials struct {
	// APIKey is the Grafana Cloud API key.
	// This field should reference a secret in production environments.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	APIKey string `json:"apiKey"`

	// InstanceID is the Grafana Cloud instance identifier.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	InstanceID string `json:"instanceId"`

	// Endpoint is the OTLP endpoint URL for Grafana Cloud.
	// Example: https://otlp-endpoint-xyz.grafana.net/otlp
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https?://`
	Endpoint string `json:"endpoint"`
}

// AxiomCredentials contains credentials for Axiom integration.
type AxiomCredentials struct {
	// APIToken is the Axiom API token.
	// This field should reference a secret in production environments.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	APIToken string `json:"apiToken"`

	// Region specifies the Axiom region.
	// Common values: us, eu
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Region string `json:"region"`

	// DatasetName is the name of the Axiom dataset to send data to.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	DatasetName string `json:"datasetName"`
}

// CloudMonitoringIntegrationStatus defines the observed state of CloudMonitoringIntegration.
type CloudMonitoringIntegrationStatus struct {
	// Conditions describe the current conditions of the CloudMonitoringIntegration.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is the last time the integration successfully synced with the monitoring platform.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed CloudMonitoringIntegration.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

var _ resource.StatusSubResource = &CloudMonitoringIntegrationStatus{}

func (s *CloudMonitoringIntegrationStatus) SubResourceName() string {
	return "status"
}

func (s *CloudMonitoringIntegrationStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*CloudMonitoringIntegration).Status = *s
}

var (
	_ runtime.Object                       = &CloudMonitoringIntegration{}
	_ resource.Object                      = &CloudMonitoringIntegration{}
	_ resource.ObjectWithStatusSubResource = &CloudMonitoringIntegration{}
	_ rest.SingularNameProvider            = &CloudMonitoringIntegration{}
)

func (c *CloudMonitoringIntegration) GetObjectMeta() *metav1.ObjectMeta {
	return &c.ObjectMeta
}

func (c *CloudMonitoringIntegration) NamespaceScoped() bool {
	return false
}

func (c *CloudMonitoringIntegration) New() runtime.Object {
	return &CloudMonitoringIntegration{}
}

func (c *CloudMonitoringIntegration) NewList() runtime.Object {
	return &CloudMonitoringIntegrationList{}
}

func (c *CloudMonitoringIntegration) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "cloudmonitoringintegrations",
	}
}

func (c *CloudMonitoringIntegration) IsStorageVersion() bool {
	return true
}

func (c *CloudMonitoringIntegration) GetSingularName() string {
	return "cloudmonitoringintegration"
}

func (c *CloudMonitoringIntegration) GetStatus() resource.StatusSubResource {
	return &c.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CloudMonitoringIntegrationList contains a list of CloudMonitoringIntegration objects.
type CloudMonitoringIntegrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloudMonitoringIntegration `json:"items"`
}

var _ resource.ObjectList = &CloudMonitoringIntegrationList{}

func (l *CloudMonitoringIntegrationList) GetListMeta() *metav1.ListMeta {
	return &l.ListMeta
}
