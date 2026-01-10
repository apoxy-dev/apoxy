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
	localPrivAddr netip.Addr
	gnv           *lwtunnel.Geneve
}

// NewProxyTunnelReconciler creates a new reconciler for managing proxy tunnels.
func NewProxyTunnelReconciler(localPrivAddr netip.Addr) *ProxyTunnelReconciler {
	return &ProxyTunnelReconciler{
		localPrivAddr: localPrivAddr,
		gnv:           lwtunnel.NewGeneve(),
	}
}

// NewProxyTunnelReconcilerWithGeneve creates a new reconciler with a custom Geneve device.
// This is useful for multicluster scenarios where each cluster needs its own device.
func NewProxyTunnelReconcilerWithGeneve(
	localPrivAddr netip.Addr,
	gnv *lwtunnel.Geneve,
) *ProxyTunnelReconciler {
	return &ProxyTunnelReconciler{
		localPrivAddr: localPrivAddr,
		gnv:           gnv,
	}
}

// TearDown removes the Geneve interface managed by this reconciler.
func (r *ProxyTunnelReconciler) TearDown() error {
	return r.gnv.TearDown()
}

// GetReplicaAddress returns the address of the given type from a replica, or empty string if not found.
func GetReplicaAddress(replica *corev1alpha2.ProxyReplicaStatus, addrType corev1alpha2.ReplicaAddressType) string {
	for _, addr := range replica.Addresses {
		if addr.Type == addrType {
			return addr.Address
		}
	}
	return ""
}

// ReplicaToEndpoint converts a ProxyReplicaStatus to a Geneve tunnel endpoint.
// Returns an error if the replica doesn't have required addresses or they are invalid.
func ReplicaToEndpoint(ctx context.Context, replica *corev1alpha2.ProxyReplicaStatus) (lwtunnel.Endpoint, error) {
	ulaAddr := GetReplicaAddress(replica, corev1alpha2.ReplicaInternalULA)
	if ulaAddr == "" {
		return lwtunnel.Endpoint{}, fmt.Errorf("replica %s missing ULA address", replica.Name)
	}

	replicaAddr, err := netip.ParseAddr(ulaAddr)
	if err != nil {
		return lwtunnel.Endpoint{}, fmt.Errorf("failed to parse replica %s ULA address %s: %w", replica.Name, ulaAddr, err)
	}

	if !replicaAddr.Is6() || !replicaAddr.IsGlobalUnicast() {
		return lwtunnel.Endpoint{}, fmt.Errorf("replica %s ULA address %s must be global unicast IPv6", replica.Name, ulaAddr)
	}

	remoteULA, err := tunnet.ULAFromPrefix(ctx, netip.PrefixFrom(replicaAddr, 128))
	if err != nil {
		return lwtunnel.Endpoint{}, fmt.Errorf("failed to generate ULA for replica %s: %w", replica.Name, err)
	}

	internalIP := GetReplicaAddress(replica, corev1alpha2.ReplicaInternalIP)
	if internalIP == "" {
		return lwtunnel.Endpoint{}, fmt.Errorf("replica %s missing internal IP address", replica.Name)
	}

	privateAddr, err := netip.ParseAddr(internalIP)
	if err != nil {
		return lwtunnel.Endpoint{}, fmt.Errorf("failed to parse replica %s internal IP %s: %w", replica.Name, internalIP, err)
	}

	if !privateAddr.IsGlobalUnicast() {
		return lwtunnel.Endpoint{}, fmt.Errorf("replica %s internal IP %s must be global unicast", replica.Name, internalIP)
	}

	return lwtunnel.Endpoint{
		Dst:    *remoteULA,
		Remote: privateAddr,
	}, nil
}

// ReconcileWithClient reconciles a Proxy using the provided client.
// This method can be used by both standard reconcilers and multicluster reconcilers.
func (r *ProxyTunnelReconciler) ReconcileWithClient(ctx context.Context, c client.Client, request ctrl.Request) (ctrl.Result, error) {
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
		ep, err := ReplicaToEndpoint(ctx, replica)
		if err != nil {
			log.Error(err, "Failed to convert replica to endpoint", "replica", replica.Name)
			continue
		}
		eps = append(eps, ep)
		log.Info("Added tunnel for replica",
			"replica", replica.Name, "dst", ep.Dst.FullPrefix(), "nve", ep.Remote)
	}

	if err := r.gnv.SyncEndpoints(ctx, eps); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to sync endpoints: %w", err)
	}

	return ctrl.Result{}, nil
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
