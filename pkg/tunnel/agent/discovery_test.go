package agent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	versionedfake "github.com/apoxy-dev/apoxy/client/versioned/fake"
)

func TestDiscoverRelays(t *testing.T) {
	relay := func(name string, ready bool, sel *metav1.LabelSelector, addrs ...string) *vpcv1alpha1.Relay {
		return &vpcv1alpha1.Relay{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       vpcv1alpha1.RelaySpec{Addresses: addrs, NetworkSelector: sel},
			Status:     vpcv1alpha1.RelayStatus{Ready: ready},
		}
	}
	prodSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}}

	cases := []struct {
		name        string
		networkTier string // label on the VPCNetwork; "" = no labels
		relays      []*vpcv1alpha1.Relay
		want        []string
	}{
		{
			name:   "nil selector serves all networks",
			relays: []*vpcv1alpha1.Relay{relay("r1", true, nil, "r1:6081")},
			want:   []string{"r1:6081"},
		},
		{
			name:   "not-ready relays are skipped",
			relays: []*vpcv1alpha1.Relay{relay("r1", false, nil, "r1:6081")},
			want:   nil,
		},
		{
			name:        "selector match includes the relay",
			networkTier: "prod",
			relays:      []*vpcv1alpha1.Relay{relay("r1", true, prodSelector, "r1:6081")},
			want:        []string{"r1:6081"},
		},
		{
			name:        "selector mismatch excludes the relay",
			networkTier: "dev",
			relays:      []*vpcv1alpha1.Relay{relay("r1", true, prodSelector, "r1:6081")},
			want:        nil,
		},
		{
			name:        "no labels never matches a selector",
			networkTier: "",
			relays:      []*vpcv1alpha1.Relay{relay("r1", true, prodSelector, "r1:6081")},
			want:        nil,
		},
		{
			name: "dedups and dial addresses across relays",
			relays: []*vpcv1alpha1.Relay{
				relay("r1", true, nil, "a:6081", "b:6081"),
				relay("r2", true, nil, "b:6081", "c:6081"),
			},
			want: []string{"a:6081", "b:6081", "c:6081"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := versionedfake.NewSimpleClientset()
			for _, r := range tc.relays {
				_, err := cs.VpcV1alpha1().Relays().Create(context.Background(), r, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			network := &vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "net"}}
			if tc.networkTier != "" {
				network.Labels = map[string]string{"tier": tc.networkTier}
			}

			got, err := DiscoverRelays(context.Background(), cs.VpcV1alpha1(), network)
			require.NoError(t, err)
			require.ElementsMatch(t, tc.want, got.UnsortedList())
		})
	}
}
