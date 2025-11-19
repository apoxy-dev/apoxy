package controllers

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/netip"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/net/lwtunnel"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

var _ reconcile.Reconciler = &TunnelNodeReconciler{}

// TunnelNodeReconciler reconciles TunnelNode objects and manages L3 Geneve tunnels.
type TunnelNodeReconciler struct {
	client.Client

	proxyName        string
	proxyReplicaName string
	localPrivAddr    netip.Addr

	gnv *lwtunnel.Geneve
}

// NewTunnelNodeReconciler returns a new TunnelNode reconciler for Geneve tunnels.
func NewTunnelNodeReconciler(
	c client.Client,
	proxyName, proxyReplicaName string,
	localPrivAddr netip.Addr,
) *TunnelNodeReconciler {
	return &TunnelNodeReconciler{
		Client: c,

		proxyName:        proxyName,
		proxyReplicaName: proxyReplicaName,
		localPrivAddr:    localPrivAddr,

		gnv: lwtunnel.NewGeneve(),
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *TunnelNodeReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)
	log.Info("Reconciling TunnelNode")

	tunnelNode := &corev1alpha.TunnelNode{}
	if err := r.Get(ctx, request.NamespacedName, tunnelNode); err != nil {
		if errors.IsNotFound(err) {
			log.Info("TunnelNode not found", "name", request.NamespacedName)
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get TunnelNode")
		return ctrl.Result{}, err
	}

	proxy := &corev1alpha2.Proxy{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.proxyName}, proxy); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Proxy not found")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Proxy")
		return ctrl.Result{}, err
	}
	rs, found := findReplicaStatus(proxy, r.proxyReplicaName)
	if !found {
		log.Info("Proxy replica not found")
		return ctrl.Result{}, nil
	}
	if rs.Address == "" {
		log.Info("Proxy replica address not found")
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
	}
	addr, err := netip.ParseAddr(rs.Address)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to parse address: %w", err)
	}

	if err := r.gnv.SetAddr(ctx, addr); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to set address: %w", err)
	}

	log = log.WithValues("proxyReplica", rs.Name, "address", addr)
	ctx = clog.IntoContext(ctx, log)
	log.Info("Reconciling tunnel device")

	var eps []lwtunnel.Endpoint

	// List all TunnelNodes to compile a list of desired endpoints.
	tunnelNodeList := &corev1alpha.TunnelNodeList{}
	if err := r.List(ctx, tunnelNodeList); err != nil {
		log.Error(err, "Failed to list TunnelNodes")
		return ctrl.Result{}, err
	}

	for _, tn := range tunnelNodeList.Items {
		for _, agent := range tn.Status.Agents {
			if agent.PrivateAddress == "" || agent.AgentAddress == "" {
				log.Info("Skipping agent with missing addresses", "agent", agent.Name, "tunnelNode", tn.Name)
				continue
			}

			nve, err := netip.ParseAddr(agent.PrivateAddress)
			if err != nil {
				log.Error(err, "Failed to parse private address",
					"agent", agent.Name, "tunnelNode", tn.Name, "privateAddress", agent.PrivateAddress)
				continue
			}

			agentAddr, err := netip.ParseAddr(agent.AgentAddress)
			if err != nil {
				log.Error(err, "Failed to parse agent address",
					"agent", agent.Name, "tunnelNode", tn.Name, "agentAddress", agent.AgentAddress)
				continue
			}
			if !agentAddr.Is6() || !agentAddr.IsGlobalUnicast() {
				log.Error(goerrors.New("overlay address must be global unicase IPv6"),
					"Invalid overlay address",
					"agent", agent.Name, "tunnelNode", tn.Name, "agentAddress", agent.AgentAddress)
				continue
			}
			agentULA, err := tunnet.ULAFromPrefix(ctx, netip.PrefixFrom(agentAddr, 96))
			if err != nil {
				log.Error(err, "Failed to generate ULA",
					"agent", agent.Name, "tunnelNode", tn.Name, "agentAddress", agent.AgentAddress)
				continue
			}

			eps = append(eps, lwtunnel.Endpoint{
				Dst:    *agentULA,
				Remote: nve,
			})
		}
	}

	if err := r.gnv.SyncEndpoints(ctx, eps); err != nil {
		log.Error(err, "Failed to sync tunnel routes")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *TunnelNodeReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := r.gnv.SetUp(ctx, r.localPrivAddr); err != nil {
		return fmt.Errorf("failed to set up tunnel device: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		//Watches(
		//	&ctrlv1alpha1.Proxy{},
		//	handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		//		return []reconcile.Request{
		//			{
		//				NamespacedName: types.NamespacedName{
		//					Name: r.proxyName + "-" + r.proxyReplicaName,
		//				},
		//			},
		//		}
		//	}),
		//	builder.WithPredicates(namePredicate(r.proxyName)),
		//).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(r)
}
