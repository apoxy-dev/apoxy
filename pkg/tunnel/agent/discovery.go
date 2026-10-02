package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	vpcclient "github.com/apoxy-dev/apoxy/client/versioned/typed/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/discovery"
)

// NewRelayLister returns a Config.RelayLister that re-fetches the VPCNetwork
// on every refresh, so relabeling it (which changes which relay selectors
// match) is picked up without an agent restart.
func NewRelayLister(vpc vpcclient.VpcV1alpha1Interface, networkName string) func(context.Context) (sets.Set[string], error) {
	return func(ctx context.Context) (sets.Set[string], error) {
		network, err := vpc.VPCNetworks().Get(ctx, networkName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("fetching VPCNetwork %q: %w", networkName, err)
		}
		return DiscoverRelays(ctx, vpc, network)
	}
}

// DiscoverRelays lists ready relays whose network selector matches the given
// network and returns their dialable underlay addresses.
func DiscoverRelays(ctx context.Context, vpc vpcclient.VpcV1alpha1Interface, network *vpcv1alpha1.VPCNetwork) (sets.Set[string], error) {
	relays, err := vpc.Relays().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing relays: %w", err)
	}
	addrs := sets.New[string]()
	for _, relay := range discovery.MatchingRelays(relays.Items, network) {
		for _, a := range relay.Spec.Addresses {
			if a = strings.TrimSpace(a); a != "" {
				addrs.Insert(a)
			}
		}
	}
	return addrs, nil
}

// refreshRelayPool periodically re-lists ready relays and swaps them into the
// pool. An empty or failed refresh leaves the current pool untouched so a
// transient apiserver blip never strands the agent.
func refreshRelayPool(
	ctx context.Context,
	lister func(context.Context) (sets.Set[string], error),
	pool *randalloc.RandAllocator[string],
	interval time.Duration,
) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastApplied sets.Set[string]
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Bound each poll regardless of the underlying client's own
			// timeout (the kubeconfig-built clientset has none): a blackholed
			// apiserver must cost one missed refresh, not a wedged goroutine.
			listCtx, cancel := context.WithTimeout(ctx, interval)
			addrs, err := lister(listCtx)
			cancel()
			if err != nil {
				slog.Warn("Failed to refresh relay list; keeping current pool", slog.Any("error", err))
				continue
			}
			if addrs.Len() == 0 {
				slog.Warn("Relay refresh returned no ready relays; keeping current pool")
				continue
			}
			// Replace wakes every blocked connection slot, so skip the churn
			// when nothing changed (the common steady state).
			if lastApplied != nil && lastApplied.Equal(addrs) {
				continue
			}
			pool.Replace(addrs)
			lastApplied = addrs
		}
	}
}
