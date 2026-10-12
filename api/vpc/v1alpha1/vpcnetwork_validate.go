package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var (
	_ resourcestrategy.Validater       = &VPCNetwork{}
	_ resourcestrategy.ValidateUpdater = &VPCNetwork{}
)

func (n *VPCNetwork) Validate(ctx context.Context) field.ErrorList {
	return n.validate()
}

// ValidateUpdate checks only spec changes, so that status writes and deletes
// of an older network do not fail.
func (n *VPCNetwork) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	if n.DeletionTimestamp != nil {
		return nil
	}
	if old, ok := obj.(*VPCNetwork); ok && apiequality.Semantic.DeepEqual(old.Spec, n.Spec) {
		return nil
	}
	return n.validate()
}

func (n *VPCNetwork) validate() field.ErrorList {
	var errs field.ErrorList
	if mtu := n.Spec.MTU; mtu != 0 && (mtu < DefaultMTU || mtu > MaxMTU) {
		errs = append(errs, field.Invalid(field.NewPath("spec", "mtu"), mtu,
			fmt.Sprintf("must be from %d to %d", DefaultMTU, MaxMTU)))
	}
	return append(errs, n.validateAgents()...)
}

// validateAgents checks spec.agents: valid names, each name one time, and the
// routes of each agent.
func (n *VPCNetwork) validateAgents() field.ErrorList {
	var errs field.ErrorList
	seen := make(map[string]bool, len(n.Spec.Agents))
	for i := range n.Spec.Agents {
		a, path := &n.Spec.Agents[i], field.NewPath("spec", "agents").Index(i)
		for _, msg := range validation.IsDNS1123Label(a.Name) {
			errs = append(errs, field.Invalid(path.Child("name"), a.Name, msg))
		}
		if seen[a.Name] {
			errs = append(errs, field.Duplicate(path.Child("name"), a.Name))
		}
		seen[a.Name] = true
		errs = append(errs, a.validateRoutes(path.Child("routes"))...)
	}
	return errs
}

// validateRoutes checks the routes of one agent: the count, each prefix one
// time, and the priority range.
func (a *VPCNetworkAgent) validateRoutes(path *field.Path) field.ErrorList {
	var errs field.ErrorList
	if len(a.Routes) > MaxAgentRoutes {
		errs = append(errs, field.TooMany(path, len(a.Routes), MaxAgentRoutes))
	}
	seen := make(map[netip.Prefix]bool, len(a.Routes))
	for i, r := range a.Routes {
		prefix, err := parseRoutePrefix(r.Prefix)
		switch {
		case err != nil:
			errs = append(errs, field.Invalid(path.Index(i).Child("prefix"), r.Prefix, err.Error()))
		case seen[prefix]:
			errs = append(errs, field.Duplicate(path.Index(i).Child("prefix"), r.Prefix))
		default:
			seen[prefix] = true
		}
		if p := r.Priority; p != nil && (*p < 0 || *p > MaxRoutePriority) {
			errs = append(errs, field.Invalid(path.Index(i).Child("priority"), *p,
				fmt.Sprintf("must be from 0 to %d", MaxRoutePriority)))
		}
	}
	return errs
}

var overlayAddressSpace = netip.MustParsePrefix(OverlayAddressSpace)

// parseRoutePrefix parses a prefix that an agent can announce. It refuses host
// bits, a default route and a prefix that overlaps the overlay address space.
func parseRoutePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	switch {
	case err != nil:
		return netip.Prefix{}, errors.New("must be an IPv4 or IPv6 prefix, for example 10.0.1.0/24")
	case p.Addr().Is4In6():
		return netip.Prefix{}, errors.New("must not be an IPv4-mapped IPv6 prefix")
	case p != p.Masked():
		return netip.Prefix{}, fmt.Errorf("must have no host bits: use %s", p.Masked())
	case p.Bits() == 0:
		return netip.Prefix{}, errors.New("must not be a default route")
	case p.Overlaps(overlayAddressSpace):
		return netip.Prefix{}, fmt.Errorf("must not overlap %s, the address range of the networks", OverlayAddressSpace)
	}
	return p, nil
}
