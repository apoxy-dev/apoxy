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

func TestRelayTLSName(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string
		want  string
	}{
		{name: "hostname", addrs: []string{"r1.relay.example.com:443"}, want: "r1.relay.example.com"},
		{name: "first hostname after addresses", addrs: []string{"10.0.0.1:6081", "[fd00::1]:6081", "r1.example.com:6081", "r2.example.com:6081"}, want: "r1.example.com"},
		{name: "hostname without port", addrs: []string{"r1.example.com"}, want: "r1.example.com"},
		{name: "addresses only", addrs: []string{"10.0.0.1:6081"}, want: "dev"},
		{name: "no addresses", want: "dev"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RelayTLSName(tc.addrs, "dev"))
		})
	}
}
