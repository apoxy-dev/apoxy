package v1alpha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/apoxy-dev/apoxy/api/resource"
	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecretStore is a named collection of secret values scoped to consumer
// surfaces. Secret values are write-only: they are set and read through the
// "values" subresource, never through the main resource, and the values
// subresource only serves reads to internal (data-plane) identities. Users
// observe key names and value digests via status.
type SecretStore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretStoreSpec   `json:"spec,omitempty"`
	Status SecretStoreStatus `json:"status,omitempty"`

	// Data holds the secret values in storage (top-level, mirroring
	// corev1.Secret). It is an internal representation: the REST layer
	// strips it from every main-resource response, and writes to it
	// through the main resource are discarded — the values subresource is
	// the only I/O path.
	// +optional
	Data map[string]string `json:"data,omitempty"`
}

type SecretStoreSpec struct {
	// Scopes authorize consumer surfaces to bind secrets from this store.
	// Each scope is "<surface>" or "<surface>:<name-glob>", e.g. "compute"
	// or "compute:frontend-*". "compute" is equivalent to "compute:*".
	// An empty list leaves the store open to all consumers in the project;
	// scopes exist to narrow access, not to grant it.
	// +optional
	Scopes []string `json:"scopes,omitempty"`
}

// SecretKeyStatus reports one key of the store: its name and a digest of its
// value, so writers can confirm writes and detect rotation without reading
// values back.
type SecretKeyStatus struct {
	Name string `json:"name"`
	// Digest is "sha256:" followed by the first 8 hex characters of the
	// SHA-256 of the value.
	Digest string `json:"digest"`
}

type SecretStoreStatus struct {
	// Keys lists the store's key names and value digests, sorted by name.
	// +optional
	Keys []SecretKeyStatus `json:"keys,omitempty"`
}

var _ resource.StatusSubResource = &SecretStoreStatus{}

func (s *SecretStoreStatus) SubResourceName() string {
	return "status"
}

func (s *SecretStoreStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*SecretStore).Status = *s
}

var (
	_ runtime.Object                       = &SecretStore{}
	_ resource.Object                      = &SecretStore{}
	_ resource.ObjectWithStatusSubResource = &SecretStore{}
	_ rest.SingularNameProvider            = &SecretStore{}
	_ resourcestrategy.Validater           = &SecretStore{}
	_ resourcestrategy.ValidateUpdater     = &SecretStore{}
	_ resourcestrategy.PrepareForCreater   = &SecretStore{}
	_ resourcestrategy.PrepareForUpdater   = &SecretStore{}
)

// Validate checks scope syntax on create.
func (s *SecretStore) Validate(ctx context.Context) field.ErrorList {
	return s.validateScopes()
}

// ValidateUpdate checks scope syntax on update.
func (s *SecretStore) ValidateUpdate(ctx context.Context, _ runtime.Object) field.ErrorList {
	return s.validateScopes()
}

func (s *SecretStore) validateScopes() field.ErrorList {
	errs := field.ErrorList{}
	p := field.NewPath("spec", "scopes")
	for i, sc := range s.Spec.Scopes {
		if _, _, err := ParseScope(sc); err != nil {
			errs = append(errs, field.Invalid(p.Index(i), sc, err.Error()))
		}
	}
	return errs
}

// ParseScope splits a scope of the form "<surface>" or "<surface>:<name-glob>"
// and validates its syntax. A bare surface is equivalent to "<surface>:*".
func ParseScope(scope string) (surface, nameGlob string, err error) {
	surface, nameGlob, found := strings.Cut(scope, ":")
	if !found {
		nameGlob = "*"
	}
	if surface == "" {
		return "", "", fmt.Errorf("scope %q: surface must not be empty", scope)
	}
	if nameGlob == "" {
		return "", "", fmt.Errorf("scope %q: name glob after ':' must not be empty", scope)
	}
	if _, err := path.Match(nameGlob, ""); err != nil {
		return "", "", fmt.Errorf("scope %q: invalid glob: %v", scope, err)
	}
	return surface, nameGlob, nil
}

// ScopeAllows reports whether the store's scopes admit the named consumer on
// the given surface. An empty scope list admits every consumer.
func (s *SecretStore) ScopeAllows(surface, name string) bool {
	if len(s.Spec.Scopes) == 0 {
		return true
	}
	for _, sc := range s.Spec.Scopes {
		sf, glob, err := ParseScope(sc)
		if err != nil || sf != surface {
			continue
		}
		if ok, _ := path.Match(glob, name); ok {
			return true
		}
	}
	return false
}

// PrepareForCreate discards any client-supplied values and derives status:
// values enter only through the values subresource.
func (s *SecretStore) PrepareForCreate(ctx context.Context) {
	s.Data = nil
	s.Status = SecretStoreStatus{}
}

// PrepareForUpdate carries the stored values through main-resource updates
// untouched: client-supplied data (and status) on the main resource is
// ignored.
func (s *SecretStore) PrepareForUpdate(ctx context.Context, old runtime.Object) {
	if o, ok := old.(*SecretStore); ok {
		s.Data = o.Data
		s.Status = o.Status
	}
}

// ComputeKeyStatus derives the status key list from a values map: names
// sorted, digests "sha256:" + first 8 hex chars of the value's SHA-256.
func ComputeKeyStatus(data map[string]string) []SecretKeyStatus {
	if len(data) == 0 {
		return nil
	}
	keys := make([]SecretKeyStatus, 0, len(data))
	for name, value := range data {
		sum := sha256.Sum256([]byte(value))
		keys = append(keys, SecretKeyStatus{
			Name:   name,
			Digest: "sha256:" + hex.EncodeToString(sum[:])[:8],
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	return keys
}

func (s *SecretStore) GetObjectMeta() *metav1.ObjectMeta {
	return &s.ObjectMeta
}

func (s *SecretStore) NamespaceScoped() bool {
	return false
}

func (s *SecretStore) New() runtime.Object {
	return &SecretStore{}
}

func (s *SecretStore) NewList() runtime.Object {
	return &SecretStoreList{}
}

func (s *SecretStore) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "secretstores",
	}
}

func (s *SecretStore) IsStorageVersion() bool {
	return true
}

func (s *SecretStore) GetSingularName() string {
	return "secretstore"
}

func (s *SecretStore) GetStatus() resource.StatusSubResource {
	return &s.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecretStoreList contains a list of SecretStore objects.
type SecretStoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretStore `json:"items"`
}

var _ resource.ObjectList = &SecretStoreList{}

func (sl *SecretStoreList) GetListMeta() *metav1.ListMeta {
	return &sl.ListMeta
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecretStoreValues is the payload of the secretstores/<name>/values
// subresource — the single path through which secret values enter and leave
// the API. PUT replaces the whole map; JSON merge-patch sets individual keys
// and deletes keys via null. GET is restricted to internal identities.
type SecretStoreValues struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Data maps key names to secret values.
	// +optional
	Data map[string]string `json:"data,omitempty"`
}
