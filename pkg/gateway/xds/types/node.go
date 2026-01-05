package types

import (
	"encoding/json"
	"fmt"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/structpb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodeMetadata represents metadata attached to an Envoy node.
// This metadata is sent with every XDS discovery request to the control plane.
// +k8s:deepcopy-gen=true
type NodeMetadata struct {
	// Name is the human-readable name of the node/proxy instance.
	Name string `json:"name,omitempty"`

	// ExternalAddress is the external/public IP address of the node reachable by clients.
	ExternalAddress string `json:"external_address,omitempty"`

	// InternalAddress is the private/internal IP address of the node.
	// This is used for internal communication or routing (e.g., Geneve tunnel endpoint).
	InternalAddress string `json:"internal_address,omitempty"`

	// ConnectedAt is the timestamp when the node was connected to the control plane.
	ConnectedAt metav1.Time `json:"connected_at,omitempty"`
}

// ToMap converts NodeMetadata to a map[string]interface{} for serialization
func (nm *NodeMetadata) ToMap() (map[string]interface{}, error) {
	// Marshal to JSON then unmarshal to map to handle all field types properly
	data, err := json.Marshal(nm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node metadata: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node metadata to map: %w", err)
	}

	// Remove empty fields
	for k, v := range result {
		if v == nil || v == "" {
			delete(result, k)
		}
	}

	return result, nil
}

// FromMap populates NodeMetadata from data.
func (nm *NodeMetadata) FromMap(data map[string]interface{}) error {
	if data == nil {
		return nil
	}

	// Marshal map to JSON then unmarshal to struct
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal map data: %w", err)
	}

	if err := json.Unmarshal(jsonData, nm); err != nil {
		return fmt.Errorf("failed to unmarshal data to node metadata: %w", err)
	}

	return nil
}

// ToStruct converts NodeMetadata to protobuf Struct for use in Envoy Node.
func (nm *NodeMetadata) ToStruct() (*structpb.Struct, error) {
	metadataMap, err := nm.ToMap()
	if err != nil {
		return nil, err
	}

	if len(metadataMap) == 0 {
		return nil, nil
	}

	return structpb.NewStruct(metadataMap)
}

// FromStruct populates NodeMetadata from a protobuf Struct
func (nm *NodeMetadata) FromStruct(s *structpb.Struct) error {
	if s == nil {
		return nil
	}

	return nm.FromMap(s.AsMap())
}

// ExtractFromDiscoveryRequest extracts NodeMetadata from an XDS DiscoveryRequest.
func ExtractFromDiscoveryRequest(req *discoveryv3.DiscoveryRequest) (*NodeMetadata, error) {
	if req == nil || req.Node == nil {
		return nil, fmt.Errorf("discovery request or node is nil")
	}

	nm := &NodeMetadata{}

	if req.Node.Metadata != nil {
		if err := nm.FromStruct(req.Node.Metadata); err != nil {
			return nil, fmt.Errorf("failed to extract metadata from discovery request: %w", err)
		}
	}

	return nm, nil
}

// ExtractFromNodeWithTime extracts NodeMetadata from an Envoy core.Node struct.
func ExtractFromNodeWithTime(node *corev3.Node, connectedAt time.Time) (*NodeMetadata, error) {
	if node == nil {
		return nil, fmt.Errorf("node is nil")
	}

	nm := &NodeMetadata{}

	if node.Metadata != nil {
		if err := nm.FromStruct(node.Metadata); err != nil {
			return nil, fmt.Errorf("failed to extract metadata from node: %w", err)
		}
	}

	nm.ConnectedAt = metav1.NewTime(connectedAt)

	return nm, nil
}

// String returns a string representation of the NodeMetadata.
func (nm *NodeMetadata) String() string {
	data, _ := json.Marshal(nm)
	return string(data)
}

// Clone creates a deep copy of the NodeMetadata.
func (nm *NodeMetadata) Clone() *NodeMetadata {
	if nm == nil {
		return nil
	}

	return &NodeMetadata{
		Name:            nm.Name,
		ExternalAddress: nm.ExternalAddress,
		InternalAddress: nm.InternalAddress,
		ConnectedAt:     nm.ConnectedAt,
	}
}

// IsEmpty returns true if all fields are empty.
func (nm *NodeMetadata) IsEmpty() bool {
	return nm.Name == "" && nm.ExternalAddress == "" && nm.InternalAddress == ""
}

// Merge merges another NodeMetadata into this one.
// Non-empty fields from other will overwrite fields in nm.
func (nm *NodeMetadata) Merge(other *NodeMetadata) {
	if other == nil {
		return
	}

	if other.Name != "" {
		nm.Name = other.Name
	}
	if other.ExternalAddress != "" {
		nm.ExternalAddress = other.ExternalAddress
	}
	if other.InternalAddress != "" {
		nm.InternalAddress = other.InternalAddress
	}
}
