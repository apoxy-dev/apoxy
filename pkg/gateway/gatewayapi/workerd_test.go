// SPDX-License-Identifier: AGPL-3.0-only

package gatewayapi

import (
	"testing"

	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsComputeServiceBackendRef(t *testing.T) {
	cases := []struct {
		name  string
		group *gwapiv1.Group
		kind  *gwapiv1.Kind
		want  bool
	}{
		{
			name:  "compute.apoxy.dev Service",
			group: ptr.To(gwapiv1.Group(GroupApoxyCompute)),
			kind:  ptr.To(gwapiv1.Kind(KindService)),
			want:  true,
		},
		{
			name:  "compute group defaults to Service kind",
			group: ptr.To(gwapiv1.Group(GroupApoxyCompute)),
			kind:  nil,
			want:  true,
		},
		{
			name:  "core Service (empty group) is not a compute Service",
			group: nil,
			kind:  ptr.To(gwapiv1.Kind(KindService)),
			want:  false,
		},
		{
			name:  "compute group but ServiceRevision kind is not matched",
			group: ptr.To(gwapiv1.Group(GroupApoxyCompute)),
			kind:  ptr.To(gwapiv1.Kind("ServiceRevision")),
			want:  false,
		},
		{
			name:  "extensions EdgeFunction is not a compute Service",
			group: ptr.To(gwapiv1.Group(GroupApoxyExtensions)),
			kind:  ptr.To(gwapiv1.Kind(KindEdgeFunction)),
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := gwapiv1.BackendObjectReference{Group: tc.group, Kind: tc.kind, Name: "echo"}
			if got := IsComputeServiceBackendRef(ref); got != tc.want {
				t.Fatalf("IsComputeServiceBackendRef = %v, want %v", got, tc.want)
			}
		})
	}
}
