package controllers

import (
	"context"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

var _ reconcile.Reconciler = &VPCNetworkReconciler{}

// VPCNetworkReconciler is the relay-side consumer of VPCNetwork objects. It
// feeds the relay the network's connect credential (for the static token
// validator), tracks its egress-gateway setting, and resolves the network's
// name to a NetworkID for the TunnelPublisher's in-process block allocation.
// It never writes VPCNetworks - the apiserver-side provisioner owns their
// identity and credentials.
type VPCNetworkReconciler struct {
	client.Client
	relay     Relay
	publisher *TunnelPublisher

	// mu guards egressByNetwork, which tracks each served network's egress-gateway
	// intent so the relay-global toggle can be recomputed deterministically
	// regardless of reconcile order.
	mu              sync.Mutex
	egressByNetwork map[string]bool
}

// NewVPCNetworkReconciler creates a relay-side VPCNetwork watcher.
func NewVPCNetworkReconciler(c client.Client, relay Relay, publisher *TunnelPublisher) *VPCNetworkReconciler {
	return &VPCNetworkReconciler{
		Client:          c,
		relay:           relay,
		publisher:       publisher,
		egressByNetwork: make(map[string]bool),
	}
}

// Reconcile propagates a VPCNetwork's credential, egress setting, and resolved
// NetworkID to the relay and publisher.
func (r *VPCNetworkReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := controllerlog.FromContext(ctx).WithValues("network", req.Name)

	var network vpcv1alpha1.VPCNetwork
	if err := r.Get(ctx, req.NamespacedName, &network); err != nil {
		if apierrors.IsNotFound(err) {
			// The network is gone: drop its egress intent and recompute the
			// relay-global toggle so a deleted network stops influencing it.
			r.removeEgressIntent(req.Name)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// Feed the static token validator this network's connect credential.
	if network.Status.Credentials != nil && network.Status.Credentials.Token != "" {
		r.relay.SetCredentials(network.Name, network.Status.Credentials.Token)
	}

	// Egress-gateway is a single relay-global toggle today; per-network routing
	// domains are not built until APO-729. Until then we recompute the toggle
	// deterministically across every served network and fail closed on a mix
	// (egress off unless all served networks want it), rather than letting the
	// last-reconciled network flip it nondeterministically.
	egress := network.Spec.EgressGateway != nil && network.Spec.EgressGateway.Enabled
	r.setEgressIntent(network.Name, egress)

	// Resolve the network's NetworkID from its overlay /72 so the publisher can
	// lease blocks for it without an apiserver read on the connect path.
	if network.Status.OverlayCIDR != "" {
		netID, err := tunnet.NetworkIDFromCIDR(network.Status.OverlayCIDR)
		if err != nil {
			log.Error(err, "Ignoring VPCNetwork with unparseable overlay CIDR", "cidr", network.Status.OverlayCIDR)
			return reconcile.Result{}, nil
		}
		r.publisher.SetNetworkID(network.Name, netID)
	}

	return reconcile.Result{}, nil
}

// setEgressIntent records a network's egress intent and pushes the recomputed
// relay-global toggle.
func (r *VPCNetworkReconciler) setEgressIntent(network string, egress bool) {
	r.mu.Lock()
	r.egressByNetwork[network] = egress
	r.mu.Unlock()
	r.pushEgress()
}

// removeEgressIntent drops a (deleted) network's egress intent and pushes the
// recomputed relay-global toggle.
func (r *VPCNetworkReconciler) removeEgressIntent(network string) {
	r.mu.Lock()
	delete(r.egressByNetwork, network)
	r.mu.Unlock()
	r.pushEgress()
}

// pushEgress recomputes and pushes the relay-global egress toggle. The global
// value is the AND of every served network's intent: egress is enabled only when
// all served networks want it, so a network that does not want a default route
// can never have one advertised on its behalf while routing domains are
// unimplemented (APO-729).
func (r *VPCNetworkReconciler) pushEgress() {
	r.mu.Lock()
	global := len(r.egressByNetwork) > 0
	for _, want := range r.egressByNetwork {
		if !want {
			global = false
			break
		}
	}
	r.mu.Unlock()

	r.relay.SetEgressGateway(global)
}

// SetupWithManager wires the watcher to VPCNetwork objects.
func (r *VPCNetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("relay-vpcnetwork").
		For(&vpcv1alpha1.VPCNetwork{}).
		Complete(r)
}
