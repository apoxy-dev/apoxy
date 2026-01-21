package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apirest "k8s.io/apiserver/pkg/registry/rest"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/builder/resource"
)

type RateLimitUnit string

const (
	// RateLimitUnitSecond is the unit of time for the rate limit.
	RateLimitUnitSecond RateLimitUnit = "Second"
	// RateLimitUnitMinute is the unit of time for the rate limit.
	RateLimitUnitMinute RateLimitUnit = "Minute"
	// RateLimitUnitHour is the unit of time for the rate limit.
	RateLimitUnitHour RateLimitUnit = "Hour"
	// RateLimitUnitDay is the unit of time for the rate limit.
	RateLimitUnitDay RateLimitUnit = "Day"
)

type RateLimitPolicy struct {
	// Unit of time for the rate limit.
	Unit RateLimitUnit `json:"unit,omitempty"`

	// How many requests are allowed per unit.
	// 0 means no requests are allowed.
	RequestsPerUnit uint32 `json:"requestsPerUnit,omitempty"`

	// Sets unlimited requests per unit.
	// +optional
	Unlimited bool `json:"unlimited,omitempty"`
}

type RateLimitDescriptor struct {
	// Key is the key of the descriptor.
	Key string `json:"key,omitempty"`

	// Value is the value of the descriptor.
	// +optional
	Value string `json:"value,omitempty"`

	// RateLimit defines the rate limit policy for the descriptor.
	// +optional
	RateLimit *RateLimitPolicy `json:"rateLimit,omitempty"`

	// Whether descriptor is in "shadow mode" which means that the rate limit
	// is not enforced but the requests are logged.
	ShadowMode bool `json:"shadowMode,omitempty"`
}

type RateLimitSpec struct {
	// A list of rate limit descriptors.
	Descriptors []*RateLimitDescriptor `json:"descriptors,omitempty"`
}

// RateLimitPhase is the current state of the rate limit.
type RateLimitPhase string

const (
	// RateLimitPhasePending is the state when the rate limit is pending.
	RateLimitPhasePending RateLimitPhase = "Pending"

	// RateLimitPhaseActive is the state when the rate limit is active.
	RateLimitPhaseActive RateLimitPhase = "Active"

	// RateLimitPhaseShadow is the state when the rate limit is in shadow mode.
	// In shadow mode, the rate limit is not enforced but the requests are logged.
	RateLimitPhaseShadow RateLimitPhase = "Shadow"
)

type RateLimitStatus struct {
	// Phase is the current state of the rate limit.
	Phase RateLimitPhase `json:"phase,omitempty"`

	// Number of rate limit requests within the limit.
	WithinLimit int64 `json:"withinLimit,omitempty"`

	// Number of rate limit requests that exceeded the limit.
	OverLimit int64 `json:"overLimit,omitempty"`

	// Total number of rate limit requests.
	TotalRequests int64 `json:"totalRequests,omitempty"`
}

var _ resource.StatusSubResource = &RateLimitStatus{}

func (ps *RateLimitStatus) SubResourceName() string {
	return "status"
}

func (ps *RateLimitStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*RateLimit).Status = *ps
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type RateLimit struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RateLimitSpec   `json:"spec,omitempty"`
	Status RateLimitStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &RateLimit{}
	_ resource.Object                      = &RateLimit{}
	_ resource.ObjectWithStatusSubResource = &RateLimit{}
	_ apirest.SingularNameProvider            = &RateLimit{}
)

func (p *RateLimit) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *RateLimit) NamespaceScoped() bool {
	return false
}

func (p *RateLimit) New() runtime.Object {
	return &RateLimit{}
}

func (p *RateLimit) NewList() runtime.Object {
	return &RateLimitList{}
}

func (p *RateLimit) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "ratelimits",
	}
}

func (p *RateLimit) IsStorageVersion() bool {
	return true
}

func (p *RateLimit) GetSingularName() string {
	return "ratelimit"
}

func (p *RateLimit) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RateLimitList contains a list of RateLimit objects.
type RateLimitList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RateLimit `json:"items"`
}

var _ resource.ObjectList = &RateLimitList{}

func (pl *RateLimitList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}
