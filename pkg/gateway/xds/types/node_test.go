package types

import (
	"encoding/json"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestNodeMetadata(t *testing.T) {
	tests := []struct {
		name string
		nm   *NodeMetadata
		want map[string]interface{}
	}{
		{
			name: "with all fields",
			nm: &NodeMetadata{
				Name:           "proxy-1",
				PrivateAddress: "10.0.0.1",
			},
			want: map[string]interface{}{
				"name":            "proxy-1",
				"private_address": "10.0.0.1",
			},
		},
		{
			name: "with name only",
			nm: &NodeMetadata{
				Name: "proxy-2",
			},
			want: map[string]interface{}{
				"name": "proxy-2",
			},
		},
		{
			name: "with private address only",
			nm: &NodeMetadata{
				PrivateAddress: "192.168.1.10",
			},
			want: map[string]interface{}{
				"private_address": "192.168.1.10",
			},
		},
		{
			name: "empty metadata",
			nm:   &NodeMetadata{},
			want: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.nm.ToMap()
			if err != nil {
				t.Fatalf("ToMap() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ToMap() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodeMetadata_FromMap(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]interface{}
		want    *NodeMetadata
		wantErr bool
	}{
		{
			name: "valid data",
			data: map[string]interface{}{
				"name":            "test-proxy",
				"private_address": "10.1.2.3",
			},
			want: &NodeMetadata{
				Name:           "test-proxy",
				PrivateAddress: "10.1.2.3",
			},
		},
		{
			name: "partial data",
			data: map[string]interface{}{
				"name": "proxy-only-name",
			},
			want: &NodeMetadata{
				Name: "proxy-only-name",
			},
		},
		{
			name: "empty map",
			data: map[string]interface{}{},
			want: &NodeMetadata{},
		},
		{
			name: "nil map",
			data: nil,
			want: &NodeMetadata{},
		},
		{
			name: "extra fields ignored",
			data: map[string]interface{}{
				"name":            "proxy-x",
				"private_address": "172.16.0.1",
				"extra_field":     "ignored",
				"another":         123,
			},
			want: &NodeMetadata{
				Name:           "proxy-x",
				PrivateAddress: "172.16.0.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nm := &NodeMetadata{}
			err := nm.FromMap(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, nm); diff != "" {
					t.Errorf("FromMap() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestNodeMetadata_ToStruct(t *testing.T) {
	tests := []struct {
		name    string
		nm      *NodeMetadata
		wantNil bool
	}{
		{
			name: "with data",
			nm: &NodeMetadata{
				Name:           "envoy-1",
				PrivateAddress: "10.0.0.5",
			},
			wantNil: false,
		},
		{
			name:    "empty metadata",
			nm:      &NodeMetadata{},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.nm.ToStruct()
			if err != nil {
				t.Fatalf("ToStruct() error = %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Errorf("ToStruct() = %v, want nil", got)
				}
			} else {
				if got == nil {
					t.Errorf("ToStruct() = nil, want non-nil")
				} else {
					// Verify the struct contains the expected fields
					fields := got.GetFields()
					if !tt.nm.IsEmpty() {
						if tt.nm.Name != "" {
							if v, ok := fields["name"]; !ok || v.GetStringValue() != tt.nm.Name {
								t.Errorf("ToStruct() name = %v, want %v", v.GetStringValue(), tt.nm.Name)
							}
						}
						if tt.nm.PrivateAddress != "" {
							if v, ok := fields["private_address"]; !ok || v.GetStringValue() != tt.nm.PrivateAddress {
								t.Errorf("ToStruct() private_address = %v, want %v", v.GetStringValue(), tt.nm.PrivateAddress)
							}
						}
					}
				}
			}
		})
	}
}

func TestNodeMetadata_FromStruct(t *testing.T) {
	tests := []struct {
		name    string
		struct_ *structpb.Struct
		want    *NodeMetadata
		wantErr bool
	}{
		{
			name: "valid struct",
			struct_: func() *structpb.Struct {
				s, _ := structpb.NewStruct(map[string]interface{}{
					"name":            "from-struct",
					"private_address": "192.168.0.1",
				})
				return s
			}(),
			want: &NodeMetadata{
				Name:           "from-struct",
				PrivateAddress: "192.168.0.1",
			},
		},
		{
			name:    "nil struct",
			struct_: nil,
			want:    &NodeMetadata{},
		},
		{
			name: "empty struct",
			struct_: func() *structpb.Struct {
				s, _ := structpb.NewStruct(map[string]interface{}{})
				return s
			}(),
			want: &NodeMetadata{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nm := &NodeMetadata{}
			err := nm.FromStruct(tt.struct_)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromStruct() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, nm); diff != "" {
					t.Errorf("FromStruct() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestExtractFromDiscoveryRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *discoveryv3.DiscoveryRequest
		want    *NodeMetadata
		wantErr bool
	}{
		{
			name: "valid request with metadata",
			req: func() *discoveryv3.DiscoveryRequest {
				metadata, _ := structpb.NewStruct(map[string]interface{}{
					"name":            "discovery-node",
					"private_address": "172.31.0.1",
				})
				return &discoveryv3.DiscoveryRequest{
					Node: &corev3.Node{
						Id:       "req-node",
						Cluster:  "req-cluster",
						Metadata: metadata,
					},
				}
			}(),
			want: &NodeMetadata{
				Name:           "discovery-node",
				PrivateAddress: "172.31.0.1",
			},
		},
		{
			name: "request without metadata",
			req: &discoveryv3.DiscoveryRequest{
				Node: &corev3.Node{
					Id:      "req-node",
					Cluster: "req-cluster",
				},
			},
			want: &NodeMetadata{},
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name:    "request with nil node",
			req:     &discoveryv3.DiscoveryRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractFromDiscoveryRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractFromDiscoveryRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("ExtractFromDiscoveryRequest() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestNodeMetadata_Clone(t *testing.T) {
	tests := []struct {
		name string
		nm   *NodeMetadata
	}{
		{
			name: "with data",
			nm: &NodeMetadata{
				Name:           "original",
				PrivateAddress: "10.20.30.40",
			},
		},
		{
			name: "empty",
			nm:   &NodeMetadata{},
		},
		{
			name: "nil",
			nm:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.nm.Clone()
			if tt.nm == nil {
				if got != nil {
					t.Errorf("Clone() = %v, want nil", got)
				}
			} else {
				if diff := cmp.Diff(tt.nm, got); diff != "" {
					t.Errorf("Clone() mismatch (-want +got):\n%s", diff)
				}
				// Ensure it's a deep copy
				if got != nil && tt.nm.Name != "" {
					got.Name = "modified"
					if tt.nm.Name == "modified" {
						t.Error("Clone() did not create a deep copy")
					}
				}
			}
		})
	}
}

func TestNodeMetadata_IsEmpty(t *testing.T) {
	tests := []struct {
		name string
		nm   *NodeMetadata
		want bool
	}{
		{
			name: "empty",
			nm:   &NodeMetadata{},
			want: true,
		},
		{
			name: "with name",
			nm:   &NodeMetadata{Name: "test"},
			want: false,
		},
		{
			name: "with private address",
			nm:   &NodeMetadata{PrivateAddress: "10.0.0.1"},
			want: false,
		},
		{
			name: "with both",
			nm: &NodeMetadata{
				Name:           "test",
				PrivateAddress: "10.0.0.1",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nm.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNodeMetadata_Merge(t *testing.T) {
	tests := []struct {
		name  string
		nm    *NodeMetadata
		other *NodeMetadata
		want  *NodeMetadata
	}{
		{
			name: "merge both fields",
			nm:   &NodeMetadata{},
			other: &NodeMetadata{
				Name:           "merged-name",
				PrivateAddress: "10.1.1.1",
			},
			want: &NodeMetadata{
				Name:           "merged-name",
				PrivateAddress: "10.1.1.1",
			},
		},
		{
			name: "overwrite existing",
			nm: &NodeMetadata{
				Name:           "original",
				PrivateAddress: "192.168.1.1",
			},
			other: &NodeMetadata{
				Name:           "updated",
				PrivateAddress: "192.168.2.2",
			},
			want: &NodeMetadata{
				Name:           "updated",
				PrivateAddress: "192.168.2.2",
			},
		},
		{
			name: "partial merge",
			nm: &NodeMetadata{
				Name:           "keep-this",
				PrivateAddress: "10.0.0.1",
			},
			other: &NodeMetadata{
				PrivateAddress: "10.0.0.2",
			},
			want: &NodeMetadata{
				Name:           "keep-this",
				PrivateAddress: "10.0.0.2",
			},
		},
		{
			name: "merge with nil",
			nm: &NodeMetadata{
				Name: "unchanged",
			},
			other: nil,
			want: &NodeMetadata{
				Name: "unchanged",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.nm.Merge(tt.other)
			if diff := cmp.Diff(tt.want, tt.nm); diff != "" {
				t.Errorf("Merge() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodeMetadata_String(t *testing.T) {
	nm := &NodeMetadata{
		Name:           "string-test",
		PrivateAddress: "10.5.5.5",
	}

	got := nm.String()

	// Parse the JSON string to verify it's valid
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(got), &result); err != nil {
		t.Errorf("String() produced invalid JSON: %v", err)
	}

	// Check the content
	if result["name"] != "string-test" {
		t.Errorf("String() name = %v, want %v", result["name"], "string-test")
	}
	if result["private_address"] != "10.5.5.5" {
		t.Errorf("String() private_address = %v, want %v", result["private_address"], "10.5.5.5")
	}
}

func TestNodeMetadata_Integration(t *testing.T) {
	// Test a full round-trip: struct -> map -> struct
	original := &NodeMetadata{
		Name:           "integration-test",
		PrivateAddress: "172.16.0.100",
	}

	// Convert to map
	m, err := original.ToMap()
	if err != nil {
		t.Fatalf("ToMap() error = %v", err)
	}

	// Create new instance from map
	fromMap := &NodeMetadata{}
	if err := fromMap.FromMap(m); err != nil {
		t.Fatalf("FromMap() error = %v", err)
	}

	// Should be equal
	if diff := cmp.Diff(original, fromMap); diff != "" {
		t.Errorf("Round-trip through map failed (-original +fromMap):\n%s", diff)
	}

	// Convert to protobuf struct
	pbStruct, err := original.ToStruct()
	if err != nil {
		t.Fatalf("ToStruct() error = %v", err)
	}

	// Create new instance from protobuf struct
	fromStruct := &NodeMetadata{}
	if err := fromStruct.FromStruct(pbStruct); err != nil {
		t.Fatalf("FromStruct() error = %v", err)
	}

	// Should be equal
	if diff := cmp.Diff(original, fromStruct); diff != "" {
		t.Errorf("Round-trip through struct failed (-original +fromStruct):\n%s", diff)
	}
}

func BenchmarkNodeMetadata_ToMap(b *testing.B) {
	nm := &NodeMetadata{
		Name:           "benchmark-node",
		PrivateAddress: "10.10.10.10",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := nm.ToMap()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNodeMetadata_ToStruct(b *testing.B) {
	nm := &NodeMetadata{
		Name:           "benchmark-node",
		PrivateAddress: "10.10.10.10",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := nm.ToStruct()
		if err != nil {
			b.Fatal(err)
		}
	}
}
