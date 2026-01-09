package tunnel

import (
	"context"
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/net/lwtunnel"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

const (
	// Default configuration for proxy tunnels
	defaultProxyGeneveDev  = "proxy-gnv0"
	defaultProxyGenevePort = 6082
	defaultProxyGeneveVNI  = 200
	defaultProxyGeneveMTU  = 1400
)

// ProxyTunnelReconciler reconciles Proxy objects and manages L3 Geneve tunnels
// to proxy replicas.
type ProxyTunnelReconciler struct {
	client.Client

	localPrivAddr netip.Addr

	gnv *lwtunnel.Geneve
}

// NewProxyTunnelReconciler creates a new reconciler for managing proxy tunnels.
func NewProxyTunnelReconciler(
	c client.Client,
	localPrivAddr netip.Addr,
) *ProxyTunnelReconciler {
	return &ProxyTunnelReconciler{
		Client: c,

		localPrivAddr: localPrivAddr,

		gnv: lwtunnel.NewGeneve(),
	}
}

// getReplicaAddress returns the address of the given type from a replica, or empty string if not found.
func getReplicaAddress(replica *corev1alpha2.ProxyReplicaStatus, addrType corev1alpha2.ReplicaAddressType) string {
	for _, addr := range replica.Addresses {
		if addr.Type == addrType {
			return addr.Address
		}
	}
	return ""
}

// ReconcileWithClient reconciles a Proxy using the provided client.
// This method can be used by both standard reconcilers and multicluster reconcilers.
func (r *ProxyTunnelReconciler) ReconcileWithClient(ctx context.Context, c client.Client, request reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)

	log.Info("Reconciling Proxy tunnels", "proxy", request.Name)

	proxy := &corev1alpha2.Proxy{}
	if err := c.Get(ctx, request.NamespacedName, proxy); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Proxy not found, cleaning up Geneve interface")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get proxy: %w", err)
	}

	ctx = clog.IntoContext(ctx, log)

	var eps []lwtunnel.Endpoint
	for _, replica := range proxy.Status.Replicas {
		ulaAddr := getReplicaAddress(replica, corev1alpha2.ReplicaInternalULA)
		if ulaAddr == "" {
			log.Info("Skipping replica with no ULA address", "replica", replica.Name)
			continue
		}

		replicaAddr, err := netip.ParseAddr(ulaAddr)
		if err != nil {
			log.Error(err, "Failed to parse replica ULA address",
				"replica", replica.Name, "address", ulaAddr)
			continue
		}

		if !replicaAddr.Is6() || !replicaAddr.IsGlobalUnicast() {
			log.Error(fmt.Errorf("invalid address"), "Replica ULA address must be global unicast IPv6",
				"replica", replica.Name, "address", ulaAddr)
			continue
		}

		remoteULA, err := tunnet.ULAFromPrefix(ctx, netip.PrefixFrom(replicaAddr, 128))
		if err != nil {
			log.Error(err, "Failed to generate ULA for replica",
				"replica", replica.Name, "address", replicaAddr)
			continue
		}

		internalIP := getReplicaAddress(replica, corev1alpha2.ReplicaInternalIP)
		if internalIP == "" {
			log.Info("Skipping replica with no internal IP address", "replica", replica.Name)
			continue
		}
		privateAddr, err := netip.ParseAddr(internalIP)
		if err != nil {
			log.Error(err, "Failed to parse internal IP address",
				"replica", replica.Name, "address", internalIP)
			continue
		}
		if !privateAddr.IsGlobalUnicast() {
			log.Error(fmt.Errorf("invalid address"), "Internal IP address must be global unicast",
				"replica", replica.Name, "address", internalIP)
			continue
		}

		eps = append(eps, lwtunnel.Endpoint{
			Dst:    *remoteULA,
			Remote: privateAddr,
		})

		log.Info("Added tunnel for replica",
			"replica", replica.Name, "dst", replicaAddr, "nve", privateAddr)
	}

	if err := r.gnv.SyncEndpoints(ctx, eps); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to sync endpoints: %w", err)
	}

	return ctrl.Result{}, nil
}

// Reconcile implements reconcile.Reconciler using the embedded client.
func (r *ProxyTunnelReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	return r.ReconcileWithClient(ctx, r.Client, request)
}

// SetupWithManager sets up the controller with the Controller Manager.
func SetupWithManager(ctx context.Context, mgr ctrl.Manager, r *ProxyTunnelReconciler) error {
	if err := r.gnv.SetUp(ctx, r.localPrivAddr); err != nil {
		return fmt.Errorf("failed to set up global network view: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.Proxy{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			return r.ReconcileWithClient(ctx, mgr.GetClient(), req)
		}))
}
