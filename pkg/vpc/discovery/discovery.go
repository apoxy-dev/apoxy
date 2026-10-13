// Package discovery picks the relays that serve a VPC network. Agents, the
// enroll endpoint and in-shard dialers use it, so they agree on the set.
package discovery

import (
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

// MatchingRelays returns the ready relays whose network selector matches
// network. A relay with a nil selector serves all networks.
func MatchingRelays(relays []vpcv1alpha1.Relay, network *vpcv1alpha1.VPCNetwork) []*vpcv1alpha1.Relay {
	var out []*vpcv1alpha1.Relay
	for i := range relays {
		relay := &relays[i]
		if !relay.Status.Ready {
			continue
		}
		if relay.Spec.NetworkSelector != nil {
			sel, err := metav1.LabelSelectorAsSelector(relay.Spec.NetworkSelector)
			if err != nil {
				// One bad Relay object must not stop the list for all networks.
				slog.Warn("Skipping relay with an invalid network selector",
					slog.String("relay", relay.Name),
					slog.Any("error", err))
				continue
			}
			if !sel.Matches(labels.Set(network.Labels)) {
				continue
			}
		}
		out = append(out, relay)
	}
	return out
}
