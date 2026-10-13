package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

func TestMatchingRelays(t *testing.T) {
	relay := func(name string, ready bool, sel *metav1.LabelSelector) vpcv1alpha1.Relay {
		return vpcv1alpha1.Relay{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       vpcv1alpha1.RelaySpec{Addresses: []string{name + ":6081"}, NetworkSelector: sel},
			Status:     vpcv1alpha1.RelayStatus{Ready: ready},
		}
	}
	prod := &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}}
	bad := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: "Bad"}}}
	cases := []struct {
		name   string
		labels map[string]string
		relays []vpcv1alpha1.Relay
		want   []string
	}{
		{name: "nil selector", relays: []vpcv1alpha1.Relay{relay("r1", true, nil)}, want: []string{"r1"}},
		{name: "not ready", relays: []vpcv1alpha1.Relay{relay("r1", false, nil)}},
		{name: "selector match", labels: map[string]string{"tier": "prod"}, relays: []vpcv1alpha1.Relay{relay("r1", true, prod)}, want: []string{"r1"}},
		{name: "selector mismatch", labels: map[string]string{"tier": "dev"}, relays: []vpcv1alpha1.Relay{relay("r1", true, prod)}},
		{name: "no labels", relays: []vpcv1alpha1.Relay{relay("r1", true, prod)}},
		{name: "bad selector", relays: []vpcv1alpha1.Relay{relay("r1", true, bad), relay("r2", true, nil)}, want: []string{"r2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			network := &vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "net", Labels: tc.labels}}
			var got []string
			for _, r := range MatchingRelays(tc.relays, network) {
				got = append(got, r.Name)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
