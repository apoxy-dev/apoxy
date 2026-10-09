package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVPCNetworkValidate(t *testing.T) {
	// The numbers are those of the API: a client can set 1280 to 1372.
	cases := []struct {
		name    string
		mtu     int32
		wantErr bool
	}{
		{name: "unset", mtu: 0},
		{name: "default", mtu: DefaultMTU},
		{name: "max", mtu: MaxMTU},
		{name: "lowest number", mtu: 1280},
		{name: "one below the lowest number", mtu: 1279, wantErr: true},
		{name: "largest number", mtu: 1372},
		{name: "one above the largest number", mtu: 1373, wantErr: true},
		{name: "largest number of older builds", mtu: 1412, wantErr: true},
		{name: "below the IPv6 minimum", mtu: DefaultMTU - 1, wantErr: true},
		{name: "above the max", mtu: MaxMTU + 1, wantErr: true},
		{name: "negative", mtu: -1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}, Spec: VPCNetworkSpec{MTU: tc.mtu}}
			errs := n.Validate(context.Background())
			if got := len(errs) > 0; got != tc.wantErr {
				t.Errorf("Validate() = %v, want error %v", errs, tc.wantErr)
			}
			if tc.wantErr && len(errs) == 1 {
				if got, want := errs[0].Field+": "+errs[0].Detail, "spec.mtu: must be from 1280 to 1372"; got != want {
					t.Errorf("Validate() error = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestVPCNetworkValidateUpdate(t *testing.T) {
	bad := &VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}, Spec: VPCNetworkSpec{MTU: 9000}}
	cases := []struct {
		name    string
		old     *VPCNetwork
		new     *VPCNetwork
		wantErr bool
	}{
		{name: "spec unchanged", old: bad, new: bad.DeepCopy()},
		{name: "deleted", old: bad, new: func() *VPCNetwork {
			n := bad.DeepCopy()
			n.DeletionTimestamp = &metav1.Time{}
			n.Spec.MTU = 9001
			return n
		}()},
		{name: "spec changed to a bad MTU", old: &VPCNetwork{}, new: bad.DeepCopy(), wantErr: true},
		{name: "spec changed to a good MTU", old: bad, new: &VPCNetwork{Spec: VPCNetworkSpec{MTU: 1372}}},
		{name: "spec changed to the largest MTU of older builds", old: &VPCNetwork{}, new: &VPCNetwork{Spec: VPCNetworkSpec{MTU: 1412}}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := tc.new.ValidateUpdate(context.Background(), tc.old)
			if got := len(errs) > 0; got != tc.wantErr {
				t.Errorf("ValidateUpdate() = %v, want error %v", errs, tc.wantErr)
			}
		})
	}
}
